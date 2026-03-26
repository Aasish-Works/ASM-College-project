from __future__ import annotations

from datetime import datetime


EXPLOIT_MATURITY_FACTOR = {
    "none": 0.5,
    "poc": 1.0,
    "weaponized": 1.5,
}

EXPOSURE_FACTOR = {
    "internal": 1.0,
    "api": 1.6,
    "cloud": 1.7,
    "external": 2.0,
    "public": 2.0,
    "third_party": 1.4,
}

THREAT_CONTEXT_FACTOR = {
    "normal": 1.0,
    "targeted": 1.6,
    "exploited_in_wild": 2.0,
    "ransomware": 2.5,
}

MAX_ENTERPRISE_RISK_RAW = 10.0 * 1.0 * 1.5 * 2.0 * 5.0 * 2.5


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def exploit_maturity_factor(value: str | None) -> float:
    return EXPLOIT_MATURITY_FACTOR.get((value or "none").strip().lower(), 0.5)


def exposure_factor(value: str | None) -> float:
    return EXPOSURE_FACTOR.get((value or "external").strip().lower(), 2.0)


def threat_context_factor(value: str | None) -> float:
    return THREAT_CONTEXT_FACTOR.get((value or "normal").strip().lower(), 1.0)


def asset_criticality_factor(value: int | None) -> float:
    if value is None:
        return 3.0
    return clamp(float(value), 1.0, 5.0)


def time_risk_multiplier(first_seen: datetime | None, last_seen: datetime | None) -> float:
    reference = last_seen or datetime.utcnow()
    if first_seen is None:
        return 1.0
    age_days = max((reference - first_seen).days, 0)
    return 1.0 + min(age_days / 180.0, 0.35)


def compute_enterprise_risk(
    *,
    cvss: float,
    epss: float,
    exploit_maturity: str,
    exposure: str,
    asset_criticality: int,
    threat_context: str,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
) -> dict[str, float | dict[str, float]]:
    cvss_value = clamp(cvss, 0.0, 10.0)
    epss_value = clamp(epss, 0.0, 1.0)
    exploit_factor = exploit_maturity_factor(exploit_maturity)
    exposure_multiplier = exposure_factor(exposure)
    criticality_multiplier = asset_criticality_factor(asset_criticality)
    threat_multiplier = threat_context_factor(threat_context)
    age_multiplier = time_risk_multiplier(first_seen, last_seen)

    raw_enterprise = (
        cvss_value
        * epss_value
        * exploit_factor
        * exposure_multiplier
        * criticality_multiplier
        * threat_multiplier
    )
    contextual_raw = raw_enterprise * age_multiplier
    normalized = clamp((contextual_raw / MAX_ENTERPRISE_RISK_RAW) * 100.0, 0.0, 100.0)

    return {
        "raw": round(raw_enterprise, 4),
        "score": round(normalized, 2),
        "age_multiplier": round(age_multiplier, 4),
        "factors": {
            "cvss": round(cvss_value, 2),
            "epss": round(epss_value, 5),
            "exploit_maturity": round(exploit_factor, 2),
            "exposure": round(exposure_multiplier, 2),
            "asset_criticality": round(criticality_multiplier, 2),
            "threat_context": round(threat_multiplier, 2),
        },
    }
