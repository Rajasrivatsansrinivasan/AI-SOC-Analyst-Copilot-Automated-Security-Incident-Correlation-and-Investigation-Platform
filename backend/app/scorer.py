SEV_MAP = {"low": 15, "medium": 35, "high": 60, "critical": 85}
TIER_BOOST = {"normal": 0, "important": 10, "crown_jewel": 20}

def compute_confidence(alerts: list[dict]) -> float:
    """
    Simple confidence: more diverse sources and more high severity => higher confidence.
    """
    sources = {a["source"] for a in alerts}
    sev = [a["severity"] for a in alerts]
    high_count = sum(1 for s in sev if s in ("high", "critical"))

    base = 0.45
    base += 0.08 * min(len(sources), 4)         # up to +0.32
    base += 0.06 * min(high_count, 5)           # up to +0.30
    return max(0.05, min(base, 0.98))

def compute_risk_score(alerts: list[dict], confidence: float) -> float:
    max_sev = max(SEV_MAP.get(a["severity"], 35) for a in alerts)
    tier = max((TIER_BOOST.get(a.get("asset_tier","normal"), 0) for a in alerts), default=0)
    # risk = severity weighted + confidence + asset tier
    risk = (0.65 * max_sev) + (0.25 * (confidence * 100)) + (0.10 * (tier * 5))
    return round(max(0.0, min(risk, 100.0)), 2)

def risk_to_label(risk: float) -> str:
    if risk >= 80: return "critical"
    if risk >= 60: return "high"
    if risk >= 35: return "medium"
    return "low"
