from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field, field_validator
from typing import Optional
import hmac
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="VOC Risk Engine", version="3.0.0")

# API-key authentication (X-API-Key header). When RISK_ENGINE_API_KEY is set the
# /score endpoint rejects unauthenticated requests; /health stays open so
# orchestrators/healthchecks can probe liveness without a key.
RISK_ENGINE_API_KEY = os.getenv('RISK_ENGINE_API_KEY', '')
if not RISK_ENGINE_API_KEY:
    logger.warning("RISK_ENGINE_API_KEY is not set - /score is UNAUTHENTICATED. Set it in production.")

# Tunable risk boosts (env-configurable, backward compatible defaults).
KEV_BOOST = float(os.getenv('RISK_KEV_BOOST', '2.0'))
EPSS_THRESHOLD = float(os.getenv('RISK_EPSS_THRESHOLD', '0.5'))
EPSS_BOOST = float(os.getenv('RISK_EPSS_BOOST', '1.0'))
MISP_BOOST = float(os.getenv('RISK_MISP_BOOST', '2.0'))
EXPLOIT_BOOST = float(os.getenv('RISK_EXPLOIT_BOOST', '1.5'))
EXPOSURE_MULTIPLIER = float(os.getenv('RISK_EXPOSURE_MULTIPLIER', '2.0'))
INTERNET_EXPOSED_FLOOR = float(os.getenv('RISK_INTERNET_EXPOSED_FLOOR', '1.5'))
PRODUCTION_BOOST = float(os.getenv('RISK_PRODUCTION_BOOST', '0.5'))
ATTACK_PATH_WEIGHT = float(os.getenv('RISK_ATTACK_PATH_WEIGHT', '1.0'))

# v3 scoring model (backward compatible with v2 additive boosts):
#
#   final = clamp(base + threat + exploit + exposure + asset, 0, 10)
#
#     base     = CVSS base score
#     threat   = KEV_BOOST(in_kev) + EPSS_BOOST(epss >= threshold) + MISP_BOOST(misp_threat_active)
#     exploit  = EXPLOIT_BOOST(public exploit available)
#     exposure = network_exposure * EXPOSURE_MULTIPLIER,
#                floored at INTERNET_EXPOSED_FLOOR when internet_exposed
#     asset    = contextual weight of the affected asset:
#                  criticality 5 / is_critical_asset -> base * 0.50   (v2 behaviour)
#                  criticality 4                     -> base * 0.25
#                  criticality <= 3                  -> 0
#                + PRODUCTION_BOOST when environment == production
#                + ATTACK_PATH_WEIGHT * attack_path_relevance (0-1)
#
# Every contribution lands in both machine-readable `factors`/`breakdown` and a
# human-readable `risk_factors` explanation list.


def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    """Reject /score calls without a valid key when one is configured."""
    if not RISK_ENGINE_API_KEY:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, RISK_ENGINE_API_KEY):
        raise HTTPException(status_code=401, detail="missing or invalid X-API-Key")


class RiskInput(BaseModel):
    cvss_base: float = Field(ge=0.0, le=10.0, description="Base CVSS score (0-10)")
    is_critical_asset: bool = Field(default=False, description="Asset is mission-critical")
    asset_criticality: int = Field(default=3, ge=1, le=5,
                                   description="Asset criticality 1=Low..5=Mission Critical")
    environment_production: bool = Field(default=False, description="Asset runs in production")
    internet_exposed: bool = Field(default=False, description="Asset reachable from the Internet")
    business_service: str = Field(default='', description="Business service supported by the asset")
    attack_path_relevance: float = Field(default=0.0, ge=0.0, le=1.0,
                                         description="Relevance in attack-path analysis (0-1)")
    misp_threat_active: bool = Field(default=False, description="Active threat intelligence in MISP")
    exploit_available: bool = Field(default=False, description="Public exploit available")
    network_exposure: float = Field(default=0.0, ge=0.0, le=1.0, description="Network exposure factor (0-1)")
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0, description="FIRST EPSS exploitation probability (0-1)")
    in_kev: bool = Field(default=False, description="Listed in CISA Known Exploited Vulnerabilities catalog")

    @field_validator('cvss_base')
    @classmethod
    def validate_cvss(cls, v):
        if v < 0 or v > 10:
            raise ValueError('CVSS must be between 0 and 10')
        return v

    @field_validator('epss_score')
    @classmethod
    def validate_epss(cls, v):
        if v < 0 or v > 1:
            raise ValueError('EPSS must be between 0 and 1')
        return v


class RiskOutput(BaseModel):
    risk_score: float = Field(ge=0.0, le=10.0)
    severity: str
    factors: dict
    breakdown: dict = {}
    risk_factors: list[str] = []


def _severity_for(score: float) -> str:
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def compute_risk_score(data: RiskInput) -> RiskOutput:
    explanations = []
    factors: dict = {}

    # ---- base -------------------------------------------------------------
    base = data.cvss_base
    factors["base_cvss"] = base

    # ---- threat context ----------------------------------------------------
    threat = 0.0
    if data.in_kev:
        threat += KEV_BOOST
        factors["kev_boost"] = KEV_BOOST
        explanations.append(f"Listed in CISA KEV: actively exploited (+{KEV_BOOST})")
    if data.epss_score >= EPSS_THRESHOLD:
        threat += EPSS_BOOST
        factors["epss_boost"] = EPSS_BOOST
        explanations.append(f"EPSS {data.epss_score:.2f} above threshold "
                            f"{EPSS_THRESHOLD} (+{EPSS_BOOST})")
    elif data.epss_score > 0:
        factors["epss_score"] = data.epss_score
        explanations.append(f"EPSS {data.epss_score:.2f} below threshold "
                            f"{EPSS_THRESHOLD} (no boost)")
    if data.misp_threat_active:
        threat += MISP_BOOST
        factors["misp_threat_boost"] = MISP_BOOST
        explanations.append(f"Active MISP threat context (+{MISP_BOOST})")

    # ---- exploit availability ----------------------------------------------
    exploit = EXPLOIT_BOOST if data.exploit_available else 0.0
    if exploit:
        factors["exploit_boost"] = exploit
        explanations.append(f"Public exploit available (+{exploit})")

    # ---- exposure -----------------------------------------------------------
    exposure = data.network_exposure * EXPOSURE_MULTIPLIER
    if exposure > 0:
        factors["network_exposure_boost"] = round(exposure, 2)
        explanations.append(f"Network exposure {data.network_exposure:.2f} "
                            f"(+{exposure:.2f})")
    if data.internet_exposed and exposure < INTERNET_EXPOSED_FLOOR:
        exposure = INTERNET_EXPOSED_FLOOR
        factors["internet_exposed_floor"] = INTERNET_EXPOSED_FLOOR
        explanations.append("Internet-exposed asset (exposure floor applied)")

    # ---- asset context -------------------------------------------------------
    asset = 0.0
    effective_crit = 5 if data.is_critical_asset else int(data.asset_criticality)
    if data.is_critical_asset:
        asset += base * 0.5
        factors["critical_asset_boost"] = round(base * 0.5, 2)
        explanations.append("Mission-critical asset (+50% of CVSS)")
    elif effective_crit == 4:
        asset += base * 0.25
        factors["high_criticality_boost"] = round(base * 0.25, 2)
        explanations.append("High-criticality asset (4/5) (+25% of CVSS)")
    if effective_crit != int(data.asset_criticality) or True:
        factors["asset_criticality"] = effective_crit
    if data.environment_production:
        asset += PRODUCTION_BOOST
        factors["production_boost"] = PRODUCTION_BOOST
        explanations.append(f"Production environment (+{PRODUCTION_BOOST})")
    if data.attack_path_relevance > 0:
        ap_boost = ATTACK_PATH_WEIGHT * data.attack_path_relevance
        asset += ap_boost
        factors["attack_path_boost"] = round(ap_boost, 2)
        explanations.append(f"Attack-path relevance {data.attack_path_relevance:.2f} "
                            f"(+{ap_boost:.2f})")
    if data.business_service:
        factors["business_service"] = data.business_service
        explanations.append(f"Supports business service: {data.business_service}")

    # ---- combine ---------------------------------------------------------------
    total = base + threat + exploit + exposure + asset
    final = min(round(total, 2), 10.0)
    factors["final_score"] = final

    severity = _severity_for(final)

    breakdown = {
        "base_score": round(base, 2),
        "threat_score": round(threat, 2),
        "exploit_score": round(exploit, 2),
        "exposure_score": round(exposure, 2),
        "asset_score": round(asset, 2),
        "final_risk_score": final,
        "severity": severity,
        "formula": ("min(base + threat + exploit + exposure + asset, 10); "
                    "threat=kev+epss+misp; asset=criticality+production+attack_path"),
    }
    explanations.append(f"Final risk {final}/10 -> {severity.upper()} "
                        f"(base {base:.1f} + threat {threat:.1f} + exploit {exploit:.1f}"
                        f" + exposure {exposure:.1f} + asset {asset:.1f}, capped at 10)")

    return RiskOutput(risk_score=final, severity=severity, factors=factors,
                      breakdown=breakdown, risk_factors=explanations)


@app.post("/score", response_model=RiskOutput, dependencies=[Depends(verify_api_key)])
def compute_score(data: RiskInput):
    try:
        result = compute_risk_score(data)
        logger.info(f"Scored CVE: cvss={data.cvss_base} -> risk={result.risk_score} ({result.severity})")
        return result
    except Exception as e:
        logger.error(f"Risk scoring error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok", "service": "risk-engine", "version": "3.0.0",
            "auth_required": bool(RISK_ENGINE_API_KEY)}
