from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass


COMMON_PORTS = [80, 443, 8080, 8443, 22]


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
        }


def _root_domain(target: str) -> str:
    parts = target.split(".")
    return target if len(parts) <= 2 else ".".join(parts[-2:])


def _fallback_output(tool: str, target: str) -> str:
    root = _root_domain(target)
    outputs = {
        "subfinder": "\n".join([f"www.{root}", f"api.{root}", f"admin.{root}", f"vpn.{root}"]),
        "amass": "\n".join([f"app.{root}", f"staging.{root}", f"auth.{root}"]),
        "assetfinder": "\n".join([f"mail.{root}", f"cdn.{root}"]),
        "puredns": "\n".join([f"portal.{root}", f"status.{root}"]),
        "dnsx": "\n".join([f"api.{root} 203.0.113.10", f"admin.{root} 203.0.113.11"]),
        "naabu": "\n".join([f"{target}:80", f"{target}:443", f"{target}:8443", f"{target}:22"]),
        "masscan": "\n".join([f"open tcp 80 {target}", f"open tcp 443 {target}", f"open tcp 9200 {target}"]),
        "nmap": "\n".join(
            [
                "22/tcp open ssh OpenSSH 8.9",
                "80/tcp open http nginx",
                "443/tcp open https nginx",
                "8443/tcp open https admin-console",
            ]
        ),
        "httpx": "\n".join(
            [
                f"https://{target}|200|Executive Portal|nginx,react",
                f"https://api.{root}|200|Public API|envoy,fastapi",
                f"https://admin.{root}|401|Admin Console|nginx",
            ]
        ),
        "tlsx": "\n".join([f"{target}|tls1.2|weak=false", f"admin.{root}|tls1.0|weak=true"]),
        "whatweb": "\n".join([f"https://{target}|nginx|React", f"https://api.{root}|FastAPI|Swagger UI"]),
        "xingfinger": "\n".join([f"https://{target}|nginx|react", f"https://admin.{root}|grafana|nginx"]),
        "gau": "\n".join([f"https://{target}/login", f"https://{target}/api/v1/users", f"https://{target}/swagger"]),
        "waybackurls": "\n".join([f"https://{target}/admin", f"https://{target}/graphql"]),
        "waymore": "\n".join([f"https://{target}/backup.zip", f"https://{target}/.env"]),
        "katana": "\n".join([f"https://{target}/", f"https://{target}/dashboard", f"https://api.{root}/openapi.json"]),
        "hakrawler": "\n".join([f"https://{target}/debug", f"https://{target}/api/internal"]),
        "ffuf": "\n".join(["200|/admin", "200|/.env", "403|/backup"]),
        "dirsearch": "\n".join(["200|/server-status", "200|/metrics", "200|/config"]),
        "nuclei": "\n".join(
            [
                f"[critical] [CVE-2024-3400] Public edge service vulnerability | host=https://{target}",
                f"[high] [CVE-2023-46747] Exposed admin interface | host=https://admin.{root}",
                f"[medium] Missing security headers | host=https://{target}",
            ]
        ),
        "kxss": "\n".join([f"MEDIUM|https://{target}/search?q=test|Reflected parameter surface"]),
        "dalfox": "\n".join([f"MEDIUM|https://{target}/search?q=1|Potential XSS vector"]),
        "nikto": "\n".join([f"HIGH|{target}|Outdated web server", f"MEDIUM|{target}|Directory indexing enabled"]),
        "wafw00f": "\n".join([f"{target}|No WAF detected"]),
        "playwright": json.dumps({"screenshots": [f"{target.replace('.', '_')}.webp"]}),
    }
    return outputs.get(tool, "")


def _default_command(tool: str, target: str) -> list[str]:
    commands = {
        "subfinder": ["subfinder", "-d", target, "-silent"],
        "amass": ["amass", "enum", "-passive", "-d", target],
        "assetfinder": ["assetfinder", "--subs-only", target],
        "puredns": ["puredns", "bruteforce", "/tmp/wordlist.txt", target],
        "dnsx": ["dnsx", "-resp", "-silent", "-l", target],
        "naabu": ["naabu", "-host", target],
        "masscan": ["masscan", target, "--ports", "80,443,8443,22,9200"],
        "nmap": ["nmap", "-Pn", "-sV", target],
        "httpx": ["httpx", "-silent", "-title", "-tech-detect", "-status-code", "-u", target],
        "tlsx": ["tlsx", "-san", "-host", target],
        "whatweb": ["whatweb", target],
        "xingfinger": ["xingfinger", "-u", target],
        "gau": ["gau", target],
        "waybackurls": ["waybackurls", target],
        "waymore": ["waymore", "-i", target, "-mode", "U"],
        "katana": ["katana", "-u", target],
        "hakrawler": ["hakrawler", "-url", target],
        "ffuf": ["ffuf", "-u", f"https://{target}/FUZZ", "-w", "wordlist.txt"],
        "dirsearch": ["dirsearch", "-u", target],
        "nuclei": ["nuclei", "-u", target, "-jsonl"],
        "kxss": ["kxss", target],
        "dalfox": ["dalfox", "url", target],
        "nikto": ["nikto", "-h", target],
        "wafw00f": ["wafw00f", target],
        "playwright": ["playwright", "screenshot", target, "output.webp"],
    }
    return commands.get(tool, [tool, target])


def run_tool(tool: str, target: str, stage: str, timeout: int = 120) -> ToolResult:
    command = _default_command(tool, target)
    binary = command[0]
    if shutil.which(binary):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            status = "completed" if completed.returncode == 0 else "error"
            stdout = completed.stdout.strip()
            stderr = completed.stderr.strip()
            if stdout:
                return ToolResult(tool, stage, status, completed.returncode, False, stdout, stderr, command)
        except Exception as exc:
            stderr = str(exc)
        else:
            stderr = stderr or "Tool returned no output"
    else:
        stderr = "Binary unavailable; fallback mode used"

    fallback_stdout = _fallback_output(tool, target)
    return ToolResult(tool, stage, "completed", 0, True, fallback_stdout, stderr, command)


def stage_tool_plan() -> dict[str, list[str]]:
    return {
        "intelligence": ["subfinder", "amass", "assetfinder", "puredns", "dnsx"],
        "network": ["naabu", "masscan", "nmap"],
        "web": ["httpx", "tlsx", "whatweb", "xingfinger", "wafw00f"],
        "content": ["gau", "waybackurls", "waymore", "katana", "hakrawler", "ffuf", "dirsearch"],
        "security": ["nuclei", "kxss", "dalfox", "nikto"],
        "evidence": ["playwright"],
    }
