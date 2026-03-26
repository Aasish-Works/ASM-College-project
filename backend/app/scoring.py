from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskContext:
    epss: float
    exploitability: float
    business_criticality: float
    exposure_modifier: float


def exposure_modifier(exposure_context: str) -> float:
    mapping = {
        "internet": 1.2,
        "partner": 1.0,
        "internal": 0.8,
        "isolated": 0.6,
    }
    return mapping.get(exposure_context, 1.0)


def normalize(value: float, max_value: float) -> float:
    if max_value <= 0:
        return 0.0
    return max(0.0, min(1.0, value / max_value))


def contextual_risk_score(ctx: RiskContext) -> float:
    # Weighted blend of exploitability, EPSS, and business impact.
    epss_component = normalize(ctx.epss, 1.0)
    exploit_component = normalize(ctx.exploitability, 10.0)
    business_component = normalize(ctx.business_criticality, 5.0)
    blended = (0.45 * epss_component) + (0.35 * exploit_component) + (0.20 * business_component)
    return round(min(10.0, blended * 10.0 * ctx.exposure_modifier), 2)
