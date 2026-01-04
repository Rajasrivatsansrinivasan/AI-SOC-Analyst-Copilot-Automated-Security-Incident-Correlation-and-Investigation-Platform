from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    title = Column(String(256), nullable=False)
    summary = Column(Text, nullable=False)

    severity = Column(String(32), nullable=False)        # low/medium/high/critical
    confidence = Column(Float, nullable=False)           # 0..1
    risk_score = Column(Float, nullable=False)           # 0..100

    status = Column(String(32), default="open")          # open/triaged/closed
    analyst_verdict = Column(String(32), default="unknown")  # true_positive/false_positive/unknown
    analyst_notes = Column(Text, default="")

    alerts = relationship("Alert", back_populates="incident", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)
    source = Column(String(64), nullable=False)          # ids/cloud/endpoint/auth
    alert_type = Column(String(128), nullable=False)     # e.g. "iam_key_created"
    severity = Column(String(32), nullable=False)        # low/medium/high/critical

    user = Column(String(128), default="")
    host = Column(String(128), default="")
    ip = Column(String(64), default="")
    asset_tier = Column(String(32), default="normal")    # normal/important/crown_jewel

    message = Column(Text, nullable=False)
    raw = Column(Text, default="")                       # raw json string

    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    incident = relationship("Incident", back_populates="alerts")
