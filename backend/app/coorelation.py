from sqlalchemy.orm import Session
from sqlalchemy import select
from .models import Incident, Alert


def correlate_incident(db: Session, incident_id: int) -> tuple[float, str, list[str]]:
    inc = db.execute(select(Incident).where(Incident.id == incident_id)).scalars().first()
    if not inc:
        return 0.0, "Incident not found.", ["Verify incident_id"]

    alerts = db.execute(select(Alert).where(Alert.incident_id == incident_id)).scalars().all()
    if not alerts:
        return 0.2, "No alerts associated with this incident yet.", ["Ingest alerts", "Verify ingestion pipeline"]

    # Simple scoring heuristic (works, deterministic)
    sev_weight = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 0.9}.get(inc.severity, 0.4)
    avg_conf = sum(a.confidence for a in alerts) / max(len(alerts), 1)
    conf_score = min(avg_conf / 100.0, 1.0)

    unique_signals = len(set(a.signal for a in alerts))
    signal_score = min(unique_signals / 5.0, 1.0)  # cap at 5 signals

    score = round(0.45 * sev_weight + 0.4 * conf_score + 0.15 * signal_score, 3)

    reason = (
        f"Severity={inc.severity}, Alerts={len(alerts)}, "
        f"AvgConfidence={round(avg_conf,1)}, UniqueSignals={unique_signals}"
    )

    next_steps = [
        "Validate scope and affected assets",
        "Check IAM changes, security group rules, and public exposures",
        "Contain: isolate compromised identities or endpoints",
        "Collect evidence: logs, CloudTrail, auth logs, network flow",
        "Eradicate and remediate: rotate keys, patch, tighten policies",
    ]

    return score, reason, next_steps
