# backend/app/main.py
from __future__ import annotations

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import select

from .db import Base, engine, get_db
from .models import Alert, Incident
from .schemas import AlertIn, AlertOut, IncidentOut, IncidentUpdate
from .correlate import correlate_alerts
from .scorer import compute_confidence, compute_risk_score, risk_to_label
from .explainer import build_title, explain_incident
from .playbooks import PLAYBOOKS
from .mitre import map_incident_to_mitre  # ✅ MITRE mapping

Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI SOC Analyst Copilot (Backend)")

# ✅ CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # dev only. lock to ["http://localhost:5173"] later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "ts": a.ts,
        "source": a.source,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "user": a.user or "",
        "host": a.host or "",
        "ip": a.ip or "",
        "asset_tier": a.asset_tier or "normal",
        "message": a.message,
        "raw": a.raw or "",
        "incident_id": a.incident_id,
    }


@app.get("/health")
def health():
    return {"ok": True}


# ---------------------------
# Alerts APIs
# ---------------------------

@app.post("/alerts", response_model=AlertOut)
def ingest_alert(alert_in: AlertIn, db: Session = Depends(get_db)):
    a = Alert(**alert_in.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return AlertOut(id=a.id, incident_id=a.incident_id, **alert_in.model_dump())


@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    """
    React UI uses this for timelines, charts, and searching.
    """
    alerts = db.scalars(select(Alert).order_by(Alert.ts.desc())).all()
    return [
        {
            "id": a.id,
            "ts": a.ts.isoformat(),
            "source": a.source,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "user": a.user or "",
            "host": a.host or "",
            "ip": a.ip or "",
            "asset_tier": a.asset_tier or "normal",
            "message": a.message,
            "incident_id": a.incident_id,
        }
        for a in alerts
    ]


# ---------------------------
# Incidents APIs
# ---------------------------

@app.post("/incidents/rebuild")
def rebuild_incidents(db: Session = Depends(get_db)):
    """
    Rebuild incidents from all alerts (MVP approach):
    - Deletes all existing incidents
    - Clusters alerts into incidents
    - Computes confidence/risk/severity
    - Writes incidents and links alerts
    """

    # Delete incidents (alerts stay; we unlink & relink)
    existing_incidents = db.scalars(select(Incident)).all()
    for inc in existing_incidents:
        db.delete(inc)
    db.commit()

    alerts = db.scalars(select(Alert).order_by(Alert.ts.asc())).all()
    alert_dicts = [_alert_to_dict(a) for a in alerts]

    clusters = correlate_alerts(alert_dicts)

    created = 0
    for cluster in clusters:
        conf = compute_confidence(cluster)
        risk = compute_risk_score(cluster, conf)
        sev = risk_to_label(risk)
        title = build_title(cluster)
        summary = explain_incident(cluster, sev, conf, risk)

        alert_types = sorted({c.get("alert_type", "") for c in cluster if c.get("alert_type")})
        mitre = map_incident_to_mitre(alert_types)

        inc = Incident(
            title=title,
            summary=summary,
            severity=sev,
            confidence=conf,
            risk_score=risk,
        )
        db.add(inc)
        db.commit()
        db.refresh(inc)

        # attach alerts to incident
        ids = [c["id"] for c in cluster if c.get("id") is not None]
        for alert_id in ids:
            a = db.get(Alert, alert_id)
            if a:
                a.incident_id = inc.id
        db.commit()

        created += 1

    return {"incidents_created": created, "clusters": len(clusters)}


@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    out: list[IncidentOut] = []

    for inc in incidents:
        alert_types = sorted({a.alert_type for a in inc.alerts if a.alert_type})
        mitre = map_incident_to_mitre(alert_types)

        out.append(
            IncidentOut(
                id=inc.id,
                created_at=inc.created_at,
                title=inc.title,
                summary=inc.summary,
                severity=inc.severity,
                confidence=inc.confidence,
                risk_score=inc.risk_score,
                status=inc.status,
                analyst_verdict=inc.analyst_verdict,
                analyst_notes=inc.analyst_notes,
                alerts=[
                    AlertOut(
                        id=a.id,
                        incident_id=a.incident_id,
                        ts=a.ts,
                        source=a.source,
                        alert_type=a.alert_type,
                        severity=a.severity,
                        user=a.user or "",
                        host=a.host or "",
                        ip=a.ip or "",
                        asset_tier=a.asset_tier or "normal",
                        message=a.message,
                        raw=a.raw or "",
                    )
                    for a in inc.alerts
                ],
                mitre=mitre,
            )
        )

    return out


@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_types = sorted({a.alert_type for a in inc.alerts if a.alert_type})
    mitre = map_incident_to_mitre(alert_types)

    return IncidentOut(
        id=inc.id,
        created_at=inc.created_at,
        title=inc.title,
        summary=inc.summary,
        severity=inc.severity,
        confidence=inc.confidence,
        risk_score=inc.risk_score,
        status=inc.status,
        analyst_verdict=inc.analyst_verdict,
        analyst_notes=inc.analyst_notes,
        alerts=[
            AlertOut(
                id=a.id,
                incident_id=a.incident_id,
                ts=a.ts,
                source=a.source,
                alert_type=a.alert_type,
                severity=a.severity,
                user=a.user or "",
                host=a.host or "",
                ip=a.ip or "",
                asset_tier=a.asset_tier or "normal",
                message=a.message,
                raw=a.raw or "",
            )
            for a in inc.alerts
        ],
        mitre=mitre,
    )


@app.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, patch: IncidentUpdate, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    data = patch.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(inc, k, v)

    db.commit()
    return {"updated": True, "incident_id": incident_id}


# ---------------------------
# Playbooks + remediation simulation
# ---------------------------

@app.get("/incidents/{incident_id}/playbook")
def get_playbook(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    types = {a.alert_type for a in inc.alerts if a.alert_type}
    steps = []
    for t in types:
        steps.extend(PLAYBOOKS.get(t, []))

    # de-dup by action
    seen = set()
    out = []
    for s in steps:
        action = s.get("action")
        if not action or action in seen:
            continue
        seen.add(action)
        out.append(s)

    return {"incident_id": incident_id, "steps": out}


@app.post("/incidents/{incident_id}/simulate_remediate")
def simulate_remediate(incident_id: int, payload: dict, db: Session = Depends(get_db)):
    """
    payload example: {"action": "block_ip"}
    Simulation only: appends a note and moves open -> triaged.
    """
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    action = payload.get("action", "")
    if not action:
        raise HTTPException(status_code=400, detail="action is required")

    inc.analyst_notes = (inc.analyst_notes or "") + f"\n[SIMULATED ACTION] {action} executed."
    if inc.status == "open":
        inc.status = "triaged"
    db.commit()

    return {"ok": True, "incident_id": incident_id, "simulated_action": action}


# ---------------------------
# Export
# ---------------------------

@app.get("/incidents/{incident_id}/export")
def export_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_types = sorted({a.alert_type for a in inc.alerts if a.alert_type})
    mitre = map_incident_to_mitre(alert_types)

    return {
        "id": inc.id,
        "created_at": inc.created_at.isoformat(),
        "title": inc.title,
        "severity": inc.severity,
        "confidence": inc.confidence,
        "risk_score": inc.risk_score,
        "status": inc.status,
        "analyst_verdict": inc.analyst_verdict,
        "analyst_notes": inc.analyst_notes,
        "summary": inc.summary,
        "mitre": mitre,
        "alerts": [
            {
                "ts": a.ts.isoformat(),
                "source": a.source,
                "alert_type": a.alert_type,
                "severity": a.severity,
                "user": a.user or "",
                "host": a.host or "",
                "ip": a.ip or "",
                "asset_tier": a.asset_tier or "normal",
                "message": a.message,
            }
            for a in inc.alerts
        ],
    }
