from __future__ import annotations

import json
import re
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from functools import lru_cache
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from .config import settings


COMMON_PORTS = [22, 80, 443, 8080, 8443, 9200]
COMMON_SUBDOMAIN_CANDIDATES = [
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "vpn",
    "mail",
    "auth",
    "status",
    "cdn",
    "jenkins",
    "grafana",
]
COMMON_DISCOVERY_PATHS = [
    "/",
    "/login",
    "/admin",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger",
    "/openapi.json",
    "/graphql",
    "/metrics",
    "/server-status",
    "/.env",
]
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
]
WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "sucuri": "Sucuri",
    "imperva": "Imperva",
    "incapsula": "Imperva",
    "awsalb": "AWS ALB",
}
SERVICE_MAP = {
    22: "ssh",
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
}

SCAN_PROFILES: dict[str, dict[str, list[str]]] = {
    "full_scan": {
        "intelligence": ["subfinder", "amass", "assetfinder", "puredns", "dnsx"],
        "network": ["naabu", "masscan", "nmap"],
        "web": ["httpx", "tlsx", "whatweb", "xingfinger", "wafw00f"],
        "content": ["gau", "waybackurls", "waymore", "katana", "hakrawler", "ffuf", "dirsearch"],
        "security": ["nuclei", "kxss", "dalfox", "nikto"],
        "evidence": ["playwright"],
    },
    "continuous_monitoring": {
        "intelligence": ["subfinder", "dnsx"],
        "web": ["httpx", "tlsx", "whatweb", "wafw00f"],
        "security": ["nuclei", "nikto"],
    },
    "intelligence_refresh": {
        "intelligence": ["subfinder", "amass", "assetfinder", "puredns", "dnsx"],
        "web": ["httpx", "whatweb", "xingfinger"],
        "content": ["gau", "katana"],
    },
}


@dataclass(slots=True)
class ToolSpec:
    name: str
    stage: str
    category: str
    description: str
    input_mode: str = "host"
    native_supported: bool = True
    timeout_seconds: int | None = None


@dataclass(slots=True)
class PreparedCommand:
    tool: str
    stage: str
    resolved_target: str
    command: list[str]
    stdin_text: str | None = None
    preparation_error: str | None = None


@dataclass(slots=True)
class ToolResult:
    tool: str
    stage: str
    status: str
    exit_code: int
    fallback_used: bool
    stdout: str
    stderr: str
    command: list[str]
    duration_ms: int
    resolved_target: str
    native_available: bool
    native_supported: bool
    fallback_reason: str | None = None
    artifact: dict[str, object] = field(default_factory=dict)

    def to_record(self) -> dict[str, object]:
        return {
            "tool": self.tool,
            "stage": self.stage,
            "status": self.status,
            "exit_code": self.exit_code,
            "fallback_used": self.fallback_used,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "command": self.command,
            "duration_ms": self.duration_ms,
            "resolved_target": self.resolved_target,
            "native_available": self.native_available,
            "native_supported": self.native_supported,
            "fallback_reason": self.fallback_reason,
            "artifact": self.artifact,
        }


TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec("subfinder", "intelligence", "discovery", "Passive subdomain discovery.", "host"),
    "amass": ToolSpec("amass", "intelligence", "discovery", "Broader passive subdomain enumeration.", "host"),
    "assetfinder": ToolSpec("assetfinder", "intelligence", "discovery", "Lightweight passive host collection.", "host"),
    "puredns": ToolSpec("puredns", "intelligence", "dns", "DNS brute-force expansion using a wordlist.", "host"),
    "dnsx": ToolSpec("dnsx", "intelligence", "dns", "DNS resolution and IP mapping.", "host"),
    "naabu": ToolSpec("naabu", "network", "port-scan", "Fast port discovery for live hosts.", "host"),
    "masscan": ToolSpec("masscan", "network", "port-scan", "Fast TCP exposure discovery.", "host"),
    "nmap": ToolSpec("nmap", "network", "service-detect", "Service/version fingerprinting.", "host"),
    "httpx": ToolSpec("httpx", "web", "http-probe", "HTTP probing with title, status, and tech.", "url"),
    "tlsx": ToolSpec("tlsx", "web", "tls", "TLS posture inspection.", "host"),
    "whatweb": ToolSpec("whatweb", "web", "fingerprint", "Technology fingerprinting for web apps.", "url"),
    "xingfinger": ToolSpec("xingfinger", "web", "fingerprint", "Third-party fingerprint correlation.", "url", native_supported=False),
    "wafw00f": ToolSpec("wafw00f", "web", "protection", "WAF presence detection.", "url"),
    "gau": ToolSpec("gau", "content", "url-intel", "Historical URL collection.", "host"),
    "waybackurls": ToolSpec("waybackurls", "content", "url-intel", "Wayback URL discovery.", "host"),
    "waymore": ToolSpec("waymore", "content", "url-intel", "Historical URL and parameter collection.", "host"),
    "katana": ToolSpec("katana", "content", "crawl", "Active web crawling.", "url"),
    "hakrawler": ToolSpec("hakrawler", "content", "crawl", "HTML-based URL extraction.", "url"),
    "ffuf": ToolSpec("ffuf", "content", "content-discovery", "Directory and file brute-force discovery.", "url"),
    "dirsearch": ToolSpec("dirsearch", "content", "content-discovery", "Directory and path enumeration.", "url"),
    "nuclei": ToolSpec("nuclei", "security", "vulnerability", "Template-driven security scanning.", "url"),
    "kxss": ToolSpec("kxss", "security", "xss-surface", "Parameter reflection and XSS surface checks.", "url", native_supported=False),
    "dalfox": ToolSpec("dalfox", "security", "xss", "XSS validation runner.", "url"),
    "nikto": ToolSpec("nikto", "security", "web-audit", "Legacy web server security checks.", "url"),
    "playwright": ToolSpec("playwright", "evidence", "evidence", "Screenshot capture for discovered applications.", "url", native_supported=False),
}


def _root_domain(target: str) -> str:
    parts = target.split(".")
    return target if len(parts) <= 2 else ".".join(parts[-2:])


def _normalize_target_fields(target: str) -> dict[str, str]:
    raw = (target or "").strip()
    candidate = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
    parsed = urlparse(candidate)
    host = (parsed.netloc or parsed.path or raw).strip().strip("/").lower()
    host = host.split("@")[-1].split(":")[0]
    if "/" in host:
        try:
            network = ip_network(host, strict=False)
            host = str(next(network.hosts(), network.network_address))
        except ValueError:
            pass
    return {
        "raw": raw,
        "host": host,
        "root": _root_domain(host) if host else "",
        "url": f"{parsed.scheme or 'https'}://{host}" if host else raw,
    }


def _wordlist_path() -> Path | None:
    candidate = Path(settings.default_wordlist_path)
    if candidate.exists():
        return candidate
    return None


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _resolve_host(host: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return list(dict.fromkeys(ips))
    except Exception:
        return []


def _probe_port(host: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except Exception:
        return False


def _extract_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120]


def _detect_tech(body: str, headers: httpx.Headers, url: str) -> list[str]:
    tech: list[str] = []
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    combined = f"{server} {powered}".lower()
    if "nginx" in combined:
        tech.append("nginx")
    if "apache" in combined:
        tech.append("apache")
    if "envoy" in combined:
        tech.append("envoy")
    if "iis" in combined:
        tech.append("iis")
    lower_body = body.lower()
    if "__next_data__" in lower_body:
        tech.append("next.js")
    if "wp-content" in lower_body:
        tech.append("wordpress")
    if "swagger ui" in lower_body or "openapi" in lower_body or "swagger" in url.lower():
        tech.append("swagger")
    if "grafana" in lower_body:
        tech.append("grafana")
    if "jenkins" in lower_body:
        tech.append("jenkins")
    if "react" in lower_body:
        tech.append("react")
    return _unique(tech)


def _extract_links(base_url: str, body: str) -> list[str]:
    links = re.findall(r"""(?:href|src)=["']([^"'#]+)["']""", body, re.IGNORECASE)
    resolved = []
    for link in links:
        if link.startswith(("mailto:", "javascript:", "tel:")):
            continue
        resolved.append(urljoin(base_url, link))
    return _unique([link for link in resolved if link.startswith(("http://", "https://"))])[:25]


def _waf_name(headers: httpx.Headers) -> str | None:
    rendered = " ".join(f"{key}:{value}" for key, value in headers.items()).lower()
    for needle, label in WAF_SIGNATURES.items():
        if needle in rendered:
            return label
    return None


def _tls_probe(host: str, timeout_seconds: float) -> dict[str, object] | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                version = wrapped.version() or "unknown"
                weak = version in {"TLSv1", "TLSv1.1", "SSLv3"}
                return {"version": version, "weak": weak}
    except Exception:
        return None


def _http_probe(client: httpx.Client, url: str) -> dict[str, object] | None:
    try:
        response = client.get(url)
    except Exception:
        return None
    content_type = response.headers.get("content-type", "")
    text_body = response.text[:12000] if "text" in content_type or "json" in content_type or not content_type else ""
    title = _extract_title(text_body)
    return {
        "url": str(response.url),
        "status_code": response.status_code,
        "title": title,
        "headers": dict(response.headers),
        "tech": _detect_tech(text_body, response.headers, str(response.url)),
        "links": _extract_links(str(response.url), text_body),
        "body": text_body,
    }


def _best_probe_for_host(client: httpx.Client, host: str) -> dict[str, object] | None:
    for url in (f"https://{host}", f"http://{host}"):
        probe = _http_probe(client, url)
        if probe:
            return probe
    return None


def _probe_paths(client: httpx.Client, base_url: str) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for path in COMMON_DISCOVERY_PATHS:
        try:
            response = client.get(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
        except Exception:
            continue
        if response.status_code in {200, 401, 403}:
            results.append(
                {
                    "path": path,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "title": _extract_title(response.text[:4000]),
                }
            )
    return results


def _probe_reflection(client: httpx.Client, base_url: str) -> dict[str, object] | None:
    marker = "asm_probe_reflection_check"
    try:
        response = client.get(base_url, params={"asm_probe": marker})
    except Exception:
        return None
    body = response.text[:20000]
    return {
        "url": str(response.url),
        "status_code": response.status_code,
        "reflected": marker in body,
    }


def _service_name(port: int) -> str:
    return SERVICE_MAP.get(port, "tcp")


@lru_cache(maxsize=128)
def _fallback_context(target: str) -> dict[str, object]:
    fields = _normalize_target_fields(target)
    host = fields["host"]
    timeout_seconds = max(min(settings.tool_timeout_seconds, 3), 1)
    context: dict[str, object] = {
        "host": host,
        "root": fields["root"],
        "url": fields["url"],
        "hosts": [],
        "ips": {},
        "ports": {},
        "http": {},
        "paths": {},
        "tls": {},
        "reflection": {},
        "waf": {},
    }
    if not host:
        return context

    hosts = [host]
    if fields["root"] and host == fields["root"]:
        for prefix in COMMON_SUBDOMAIN_CANDIDATES[:8]:
            candidate = f"{prefix}.{fields['root']}"
            if _resolve_host(candidate):
                hosts.append(candidate)
    hosts = _unique(hosts)[:5]
    context["hosts"] = hosts

    for entry in hosts:
        ips = _resolve_host(entry)
        if ips:
            context["ips"][entry] = ips

    scan_hosts = [entry for entry in hosts if context["ips"].get(entry)] or [host]
    scan_hosts = scan_hosts[:3]
    for entry in scan_hosts:
        open_ports = [port for port in COMMON_PORTS if _probe_port(entry, port, timeout_seconds / 2)]
        if open_ports:
            context["ports"][entry] = open_ports

    client_timeout = httpx.Timeout(timeout_seconds)
    with httpx.Client(timeout=client_timeout, verify=False, follow_redirects=True, headers={"User-Agent": "AegisASM/2.0"}) as client:
        for entry in scan_hosts:
            probe = _best_probe_for_host(client, entry)
            if not probe:
                continue
            context["http"][entry] = probe
            context["paths"][entry] = _probe_paths(client, str(probe["url"]))
            if 443 in context["ports"].get(entry, []):
                tls_result = _tls_probe(entry, timeout_seconds / 2)
                if tls_result:
                    context["tls"][entry] = tls_result
            reflection = _probe_reflection(client, str(probe["url"]))
            if reflection:
                context["reflection"][entry] = reflection
            waf_name = _waf_name(httpx.Headers(probe["headers"]))
            if waf_name:
                context["waf"][entry] = waf_name
    return context


def _partitioned_hosts(tool: str, context: dict[str, object]) -> list[str]:
    hosts = [host for host in context.get("hosts", []) if host != context.get("root")]
    if tool == "subfinder":
        return hosts[:4]
    if tool == "amass":
        return hosts[1:6]
    if tool == "assetfinder":
        return hosts[::2]
    if tool == "puredns":
        return hosts[2:6]
    return hosts


def _link_inventory(context: dict[str, object]) -> list[str]:
    links: list[str] = []
    for http_result in context.get("http", {}).values():
        links.extend(http_result.get("links", []))
    for path_results in context.get("paths", {}).values():
        links.extend(item["url"] for item in path_results)
    return _unique(links)[:40]


def _fallback_output(tool: str, target: str) -> tuple[str, dict[str, object]]:
    context = _fallback_context(target)
    host = str(context.get("host") or target)
    urls = context.get("http", {})
    paths = context.get("paths", {})
    links = _link_inventory(context)
    artifact = {"mode": "python-fallback", "context_hosts": context.get("hosts", [])}

    if tool in {"subfinder", "amass", "assetfinder", "puredns"}:
        stdout = "\n".join(_partitioned_hosts(tool, context))
        return stdout, artifact

    if tool == "dnsx":
        lines = []
        for entry, ips in context.get("ips", {}).items():
            for ip in ips:
                lines.append(f"{entry} {ip}")
        return "\n".join(lines), artifact

    if tool == "naabu":
        lines = []
        for entry, ports in context.get("ports", {}).items():
            for port in ports:
                lines.append(f"{entry}:{port}")
        return "\n".join(lines), artifact

    if tool == "masscan":
        lines = []
        for entry, ports in context.get("ports", {}).items():
            for port in ports:
                lines.append(f"open tcp {port} {entry}")
        return "\n".join(lines), artifact

    if tool == "nmap":
        lines = []
        for entry, ports in context.get("ports", {}).items():
            for port in ports:
                lines.append(f"{port}/tcp open {_service_name(port)} {entry}")
        return "\n".join(lines), artifact

    if tool == "httpx":
        lines = []
        for entry, probe in urls.items():
            tech = ",".join(probe.get("tech", []))
            title = probe.get("title") or entry
            lines.append(f"{probe['url']}|{probe['status_code']}|{title}|{tech}")
        return "\n".join(lines), artifact

    if tool == "tlsx":
        lines = []
        for entry, tls_result in context.get("tls", {}).items():
            lines.append(f"{entry}|{tls_result['version']}|weak={str(tls_result['weak']).lower()}")
        return "\n".join(lines), artifact

    if tool in {"whatweb", "xingfinger"}:
        lines = []
        for probe in urls.values():
            tech = probe.get("tech") or ["unknown"]
            lines.append("|".join([probe["url"], *tech[:4]]))
        return "\n".join(lines), artifact

    if tool in {"gau", "waybackurls", "waymore", "katana", "hakrawler"}:
        return "\n".join(links), artifact

    if tool in {"ffuf", "dirsearch"}:
        lines = []
        for path_results in paths.values():
            for item in path_results:
                if item["path"] == "/":
                    continue
                lines.append(f"{item['status_code']}|{urlparse(item['url']).path}")
        return "\n".join(_unique(lines)), artifact

    if tool == "wafw00f":
        lines = []
        for entry, probe in urls.items():
            waf_name = context.get("waf", {}).get(entry)
            lines.append(f"{entry}|{waf_name + ' detected' if waf_name else 'No WAF detected'}")
        return "\n".join(lines), artifact

    if tool == "nuclei":
        lines = []
        for entry, probe in urls.items():
            headers = {str(key).lower(): str(value) for key, value in probe.get("headers", {}).items()}
            missing = [header for header in SECURITY_HEADERS if header not in headers]
            if missing:
                lines.append(f"[medium] Missing security headers | host={probe['url']}")
            for item in paths.get(entry, []):
                path = urlparse(item["url"]).path.lower()
                if path in {"/admin", "/server-status", "/metrics"}:
                    lines.append(f"[high] Public administrative interface | host={item['url']}")
                if path in {"/swagger", "/openapi.json", "/graphql"}:
                    lines.append(f"[medium] Public API documentation exposed | host={item['url']}")
                if path == "/.env":
                    lines.append(f"[critical] Sensitive file exposed | host={item['url']}")
        if 9200 in context.get("ports", {}).get(host, []):
            lines.append(f"[high] Exposed Elasticsearch service | host=https://{host}")
        return "\n".join(_unique(lines)), artifact

    if tool == "kxss":
        lines = []
        for reflection in context.get("reflection", {}).values():
            if reflection.get("reflected"):
                lines.append(f"MEDIUM|{reflection['url']}|Reflected parameter surface")
        return "\n".join(lines), artifact

    if tool == "dalfox":
        lines = []
        for reflection in context.get("reflection", {}).values():
            if reflection.get("reflected"):
                lines.append(f"MEDIUM|{reflection['url']}|Potential reflected parameter")
        return "\n".join(lines), artifact

    if tool == "nikto":
        lines = []
        for entry, probe in urls.items():
            headers = {str(key).lower(): str(value) for key, value in probe.get("headers", {}).items()}
            server = headers.get("server")
            if server:
                lines.append(f"LOW|{entry}|Server header disclosed: {server}")
            for item in paths.get(entry, []):
                path = urlparse(item["url"]).path.lower()
                if path == "/.env":
                    lines.append(f"HIGH|{entry}|Sensitive file accessible at {path}")
                if path == "/server-status":
                    lines.append(f"MEDIUM|{entry}|Server status endpoint exposed")
        return "\n".join(_unique(lines)), artifact

    if tool == "playwright":
        return json.dumps({"screenshots": [], "note": "Native browser automation unavailable in fallback mode."}), artifact

    return "", artifact


def _prepare_command(tool: str, target: str, stage: str | None = None) -> PreparedCommand:
    spec = TOOL_SPECS.get(tool)
    if spec is None:
        return PreparedCommand(tool=tool, stage=stage or "manual", resolved_target=target, command=[], preparation_error="Unknown tool")

    fields = _normalize_target_fields(target)
    host = fields["host"]
    url = fields["url"]
    wordlist = _wordlist_path()

    if not host:
        return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=target, command=[], preparation_error="Target is empty")

    if tool == "subfinder":
        command = ["subfinder", "-d", host, "-silent"]
    elif tool == "amass":
        command = ["amass", "enum", "-passive", "-d", host]
    elif tool == "assetfinder":
        command = ["assetfinder", "--subs-only", host]
    elif tool == "puredns":
        if wordlist is None:
            return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=host, command=[], preparation_error="Wordlist not found for puredns")
        command = ["puredns", "bruteforce", str(wordlist), host]
    elif tool == "dnsx":
        command = ["dnsx", "-silent", "-resp"]
        return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=host, command=command, stdin_text=f"{host}\n")
    elif tool == "naabu":
        command = ["naabu", "-host", host]
    elif tool == "masscan":
        command = ["masscan", host, "--ports", ",".join(str(port) for port in COMMON_PORTS), "--rate", "1000"]
    elif tool == "nmap":
        command = ["nmap", "-Pn", "-sV", "-p", ",".join(str(port) for port in COMMON_PORTS), host]
    elif tool == "httpx":
        command = ["httpx", "-silent", "-title", "-tech-detect", "-status-code", "-u", url]
    elif tool == "tlsx":
        command = ["tlsx", "-silent", "-host", host]
    elif tool == "whatweb":
        command = ["whatweb", url]
    elif tool == "xingfinger":
        command = ["xingfinger", "-u", url]
    elif tool == "wafw00f":
        command = ["wafw00f", url]
    elif tool == "gau":
        command = ["gau", host]
    elif tool == "waybackurls":
        command = ["waybackurls", host]
    elif tool == "waymore":
        command = ["waymore", "-i", host, "-mode", "U"]
    elif tool == "katana":
        command = ["katana", "-silent", "-u", url]
    elif tool == "hakrawler":
        command = ["hakrawler", "-url", url]
    elif tool == "ffuf":
        if wordlist is None:
            return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=url, command=[], preparation_error="Wordlist not found for ffuf")
        command = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", str(wordlist), "-mc", "200,401,403"]
    elif tool == "dirsearch":
        command = ["dirsearch", "-u", url, "-q"]
    elif tool == "nuclei":
        command = ["nuclei", "-silent", "-u", url]
    elif tool == "kxss":
        command = ["kxss"]
        return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=url, command=command, stdin_text=f"{url}\n")
    elif tool == "dalfox":
        command = ["dalfox", "url", url, "--silence"]
    elif tool == "nikto":
        command = ["nikto", "-h", url]
    elif tool == "playwright":
        command = ["playwright", "screenshot", url, "output.webp"]
    else:
        command = [tool, host]

    return PreparedCommand(tool=tool, stage=stage or spec.stage, resolved_target=url if spec.input_mode == "url" else host, command=command)


def _native_binary(command: list[str]) -> str | None:
    return command[0] if command else None


def _native_available(command: list[str]) -> bool:
    binary = _native_binary(command)
    return bool(binary and shutil.which(binary))


def _use_native(tool: str, command: list[str]) -> tuple[bool, str | None]:
    spec = TOOL_SPECS.get(tool)
    mode = settings.native_tool_mode
    if mode == "fallback":
        return False, "Fallback mode is forced by configuration."
    if spec is None or not spec.native_supported:
        return False, "Native execution is not implemented for this tool adapter."
    if not command:
        return False, "Command could not be prepared for this tool."
    if not _native_available(command):
        return False, "Scanner binary was not found in PATH."
    return True, None


def run_tool(tool: str, target: str, stage: str, timeout: int | None = None) -> ToolResult:
    spec = TOOL_SPECS.get(tool, ToolSpec(tool, stage, "custom", "Custom tool invocation.", "host", native_supported=False))
    prepared = _prepare_command(tool, target, stage)
    command = prepared.command
    native_available = _native_available(command)
    can_use_native, fallback_reason = _use_native(tool, command)

    if prepared.preparation_error:
        can_use_native = False
        fallback_reason = prepared.preparation_error

    timeout_seconds = timeout or spec.timeout_seconds or settings.tool_timeout_seconds

    if can_use_native:
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                input=prepared.stdin_text,
                timeout=timeout_seconds,
                check=False,
            )
            duration_ms = int((time.perf_counter() - started) * 1000)
            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            if completed.returncode == 0:
                return ToolResult(
                    tool=tool,
                    stage=stage,
                    status="completed",
                    exit_code=completed.returncode,
                    fallback_used=False,
                    stdout=stdout,
                    stderr=stderr,
                    command=command,
                    duration_ms=duration_ms,
                    resolved_target=prepared.resolved_target,
                    native_available=native_available,
                    native_supported=spec.native_supported,
                    artifact={
                        "stdin_text": prepared.stdin_text,
                        "resolved_target": prepared.resolved_target,
                        "mode": "native",
                    },
                )
            fallback_reason = stderr or f"Native tool exited with code {completed.returncode}."
        except Exception as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            fallback_reason = f"Native execution failed: {exc}"
        else:
            duration_ms = duration_ms
    else:
        duration_ms = 0

    started = time.perf_counter()
    fallback_stdout, artifact = _fallback_output(tool, prepared.resolved_target or target)
    duration_ms += int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool=tool,
        stage=stage,
        status="completed",
        exit_code=0,
        fallback_used=True,
        stdout=fallback_stdout,
        stderr=fallback_reason or "Python fallback reconnaissance used.",
        command=command,
        duration_ms=duration_ms,
        resolved_target=prepared.resolved_target or target,
        native_available=native_available,
        native_supported=spec.native_supported,
        fallback_reason=fallback_reason or "Python fallback reconnaissance used.",
        artifact={
            **artifact,
            "stdin_text": prepared.stdin_text,
            "resolved_target": prepared.resolved_target or target,
        },
    )


def stage_tool_plan(scan_kind: str = "full_scan") -> dict[str, list[str]]:
    return SCAN_PROFILES.get(scan_kind, SCAN_PROFILES["full_scan"])


def scan_profiles() -> dict[str, dict[str, list[str]]]:
    return {name: {stage: list(tools) for stage, tools in plan.items()} for name, plan in SCAN_PROFILES.items()}


def tool_inventory() -> list[dict[str, object]]:
    memberships: dict[str, list[str]] = {}
    for profile_name, profile in SCAN_PROFILES.items():
        for tools in profile.values():
            for tool in tools:
                memberships.setdefault(tool, []).append(profile_name)

    inventory: list[dict[str, object]] = []
    for tool_name in sorted(TOOL_SPECS):
        spec = TOOL_SPECS[tool_name]
        prepared = _prepare_command(tool_name, "example.com", spec.stage)
        inventory.append(
            {
                "name": spec.name,
                "stage": spec.stage,
                "category": spec.category,
                "description": spec.description,
                "input_mode": spec.input_mode,
                "native_supported": spec.native_supported,
                "native_available": _native_available(prepared.command),
                "profiles": memberships.get(tool_name, []),
                "command_preview": prepared.command,
                "preparation_error": prepared.preparation_error,
            }
        )
    return inventory
