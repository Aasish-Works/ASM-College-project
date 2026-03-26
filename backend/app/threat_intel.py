from __future__ import annotations

import csv
import json
import os
from datetime import datetime

from .config import settings
from .epss import get_epss_score


SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 8.1,
    "medium": 6.0,
    "low": 3.8,
    "info": 0.0,
}


_kev_cache: set[str] | None = None
_exploit_cache: dict[str, dict[str, str]] | None = None


def _safe_float(value: str | None) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _load_kev() -> set[str]:
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    path = settings.kev_json_path
    kev: set[str] = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        vulnerabilities = payload.get("vulnerabilities") or payload.get("catalog") or []
        for item in vulnerabilities:
            cve = (item.get("cveID") or item.get("cve") or "").strip().upper()
            if cve:
                kev.add(cve)
    _kev_cache = kev
    return kev


def _load_exploitdb() -> dict[str, dict[str, str]]:
    global _exploit_cache
    if _exploit_cache is not None:
        return _exploit_cache

    path = settings.exploitdb_csv_path
    index: dict[str, dict[str, str]] = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                cve = (row.get("cve") or row.get("CVE") or "").strip().upper()
                if not cve:
                    continue
                index[cve] = {
                    "edb_id": row.get("edb_id") or row.get("id") or "",
                    "title": row.get("title") or "",
                    "type": row.get("type") or row.get("platform") or "",
                }
    _exploit_cache = index
    return index


def refresh_threat_feeds() -> dict[str, int]:
    global _kev_cache, _exploit_cache
    _kev_cache = None
    _exploit_cache = None
    return {"kev_entries": len(_load_kev()), "exploitdb_entries": len(_load_exploitdb())}


def severity_to_cvss(severity: str | None) -> float:
    return SEVERITY_TO_CVSS.get((severity or "info").strip().lower(), 0.0)


def infer_exploit_maturity(cve: str | None, title: str, severity: str, kev: bool, exploit_record: dict[str, str] | None) -> str:
    if kev:
        return "weaponized"
    if exploit_record:
        return "poc"
    title_lc = title.lower()
    if "rce" in title_lc or "deserialization" in title_lc:
        return "poc"
    if severity.lower() == "critical":
        return "poc"
    return "none"


def infer_threat_context(kev: bool, exploit_maturity: str, ransomware: bool) -> str:
    if ransomware:
        return "ransomware"
    if kev:
        return "exploited_in_wild"
    if exploit_maturity == "weaponized":
        return "targeted"
    return "normal"


def enrich_vulnerability(cve: str | None, severity: str, title: str, description: str | None = None) -> dict[str, object]:
    cve_key = (cve or "").strip().upper() or None
    kev = cve_key in _load_kev() if cve_key else False
    exploit_record = _load_exploitdb().get(cve_key) if cve_key else None
    epss = get_epss_score(cve_key) or 0.0
    exploit_maturity = infer_exploit_maturity(cve_key, title, severity, kev, exploit_record)
    threat_context = infer_threat_context(kev, exploit_maturity, ransomware=False)

    references = []
    if cve_key:
        references.append({"source": "nvd", "id": cve_key})
    if kev:
        references.append({"source": "cisa_kev", "id": cve_key})
    if exploit_record:
        references.append({"source": "exploit_db", **exploit_record})

    return {
        "cve": cve_key,
        "cvss": severity_to_cvss(severity),
        "cvss_v4": 0.0,
        "epss": epss,
        "kev": kev,
        "exploit_maturity": exploit_maturity,
        "threat_context": threat_context,
        "ransomware": False,
        "references": references,
        "last_synced_at": datetime.utcnow(),
    }


def lookup_threat_context(cve: str | None) -> dict[str, object]:
    cve_key = (cve or "").strip().upper()
    if not cve_key:
        return {"cve": None, "found": False}
    payload = enrich_vulnerability(cve_key, "medium", cve_key)
    payload["found"] = True
    return payload
