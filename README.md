AI SOC Analyst Copilot

AI SOC Analyst Copilot is a full-stack security operations (SOC) application that ingests security alerts, correlates them into incidents, and provides an analyst-centric workflow for investigation, triage, and response.
The system is designed to demonstrate how modern SOC tools combine automation with human-in-the-loop decision making.

Key Features
Alert Ingestion

REST API to ingest alerts from multiple sources (auth, cloud, endpoint, IDS, etc.)

Supports structured metadata such as user, host, IP, severity, and asset tier

Alerts are stored independently and can be reviewed before correlation

Incident Correlation

Alerts are clustered into incidents using a rebuild step

Each incident is enriched with:

Risk score

Severity label

Confidence score

Natural-language summary

Analysts explicitly control when correlation occurs, ensuring auditability

Analyst Investigation Workflow

Incident list with filtering by severity, status, and free-text search

Detailed incident view with:

Risk visualization

Incident summary

Linked alerts

MITRE ATT&CK mapping

Extracted indicators of compromise (IoCs)

Ready-to-run investigation queries

Visual Timeline

Vertical timeline view of alert events

Color-coded severity dots

Sortable by time (oldest → newest or newest → oldest)

Optimized for fast incident context building

Triage Checklist

Automatic checks (scope, IoCs, MITRE, timeline)

Manual analyst steps (containment, eradication, recovery, documentation)

Checklist progress tracking

Persisted per incident in the browser

Playbooks and Remediation Simulation

Context-aware playbooks generated from alert types

One-click remediation simulation

Actions logged per incident for audit and review

Persistence Without Backend Complexity

Action logs, checklist state, and draft notes are persisted per incident using localStorage

Page refresh does not lose analyst progress

Clean separation between analyst drafts and saved backend state

Export and Handoff

Incident JSON export

Investigator Pack export including:

Summary

Timeline

MITRE mapping

IoCs

Investigation queries

Checklist state

Action log

Architecture Overview
Backend

FastAPI

SQLAlchemy with SQLite

Modular incident scoring and explanation pipeline

REST APIs for alerts, incidents, playbooks, and exports

Designed for future real-time streaming and SOAR integrations

Frontend

React (Vite)

Axios for API communication

WebSocket client scaffolding for real-time alerts

Analyst-first UI with clear state management

No backend dependency for drafts and workflow state

Project Structure
soc-copilot/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── correlate.py
│   │   ├── scorer.py
│   │   ├── explainer.py
│   │   ├── playbooks.py
│   │   └── mitre.py
│   └── db.sqlite
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api.js
│   │   └── main.jsx
│   └── index.html
└── README.md

How to Run
Backend

Create and activate a virtual environment

python -m venv venv
venv\Scripts\activate   # Windows


Install dependencies

pip install fastapi uvicorn sqlalchemy pydantic


Start the backend

uvicorn app.main:app --reload


Backend will run at:

http://localhost:8000

Frontend

Install dependencies

npm install


Start the frontend

npm run dev


Frontend will run at:

http://localhost:5173

Example Alert Ingestion (PowerShell)
$body = @{
  ts         = "2026-01-04T12:00:00Z"
  source     = "demo"
  alert_type = "ssh_bruteforce"
  message    = "Realtime test alert"
  user       = "admin"
  host       = "web-01"
  ip         = "1.2.3.4"
  severity   = "high"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/alerts" `
  -Method POST `
  -ContentType "application/json" `
  -Body $body


After ingesting alerts, rebuild incidents:

Invoke-RestMethod -Uri "http://localhost:8000/incidents/rebuild" -Method POST

Design Philosophy

Human-in-the-loop by default

Analyst control over correlation and verdicts

Clear audit trail

Separation of automation and decision making

Demo-friendly, extensible architecture

Future Enhancements

Authentication and multi-user support

Database-backed audit logs

Live alert streaming with automatic correlation

SOAR and remediation integrations

Advanced metrics and dashboards

License

This project is provided for educational and demonstration purposes.