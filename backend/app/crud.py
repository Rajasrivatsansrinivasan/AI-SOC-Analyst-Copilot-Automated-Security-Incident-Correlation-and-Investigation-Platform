from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select
from . import models, schemas


def create_incident(db: Session, payload: schemas.IncidentCreate) -> models.Incident:
    inc = models.Incident(
        title=payload.title,
        severity=payload.severity,
        status=payload.status,
        source=payload.source,
        description=payload.description,
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return inc


def list_incidents(db: Session, limit: int = 50, offset: int = 0):
    stmt = select(models.Incident).order_by(models.Incident.created_at.desc()).offset(offset).limit(limit)
    return db.execute(stmt).scalars().all()


def get_incident(db: Session, incident_id: int):
    stmt = select(models.Incident).where(models.Incident.id == incident_id)
    return db.execute(stmt).scalars().first()


def update_incident(db: Session, incident: models.Incident, payload: schemas.IncidentUpdate) -> models.Incident:
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(incident, k, v)
    db.commit()
    db.refresh(incident)
    return incident


def delete_incident(db: Session, incident: models.Incident) -> None:
    db.delete(incident)
    db.commit()


def create_alert(db: Session, payload: schemas.AlertCreate) -> models.Alert:
    alert = models.Alert(
        incident_id=payload.incident_id,
        rule=payload.rule,
        signal=payload.signal,
        confidence=payload.confidence,
        raw_event=payload.raw_event,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def list_alerts(db: Session, limit: int = 100, offset: int = 0):
    stmt = select(models.Alert).order_by(models.Alert.created_at.desc()).offset(offset).limit(limit)
    return db.execute(stmt).scalars().all()


def upsert_investigation(db: Session, incident_id: int, payload: schemas.InvestigationBase) -> models.InvestigationNote:
    stmt = select(models.InvestigationNote).where(models.InvestigationNote.incident_id == incident_id)
    existing = db.execute(stmt).scalars().first()

    if existing:
        data = payload.model_dump(exclude_unset=True)
        for k, v in data.items():
            setattr(existing, k, v)
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return existing

    note = models.InvestigationNote(
        incident_id=incident_id,
        summary=payload.summary,
        hypothesis=payload.hypothesis,
        recommended_actions=payload.recommended_actions,
        updated_at=datetime.utcnow(),
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note
