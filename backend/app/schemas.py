from datetime import datetime
from typing import Optional, List, Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]
Status = Literal["open", "in_progress", "closed"]


class AlertBase(BaseModel):
    rule: str
    signal: str
    confidence: int = Field(ge=0, le=100, default=70)
    raw_event: Optional[str] = None


class AlertCreate(AlertBase):
    incident_id: int


class AlertOut(AlertBase):
    id: int
    incident_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class InvestigationBase(BaseModel):
    summary: Optional[str] = None
    hypothesis: Optional[str] = None
    recommended_actions: Optional[str] = None


class InvestigationOut(InvestigationBase):
    id: int
    incident_id: int
    updated_at: datetime

    class Config:
        from_attributes = True


class IncidentBase(BaseModel):
    title: str
    severity: Severity = "medium"
    status: Status = "open"
    source: str = "detector"
    description: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[Severity] = None
    status: Optional[Status] = None
    source: Optional[str] = None
    description: Optional[str] = None


class IncidentOut(IncidentBase):
    id: int
    created_at: datetime
    alerts: List[AlertOut] = []
    investigation: Optional[InvestigationOut] = None

    class Config:
        from_attributes = True


class CorrelationRequest(BaseModel):
    incident_id: int


class CorrelationResult(BaseModel):
    incident_id: int
    score: float
    reason: str
    recommended_next_steps: list[str]
