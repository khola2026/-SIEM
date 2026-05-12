from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import SessionLocal, init_db
from models import LogEntry

app = FastAPI(title="SIEM Backend V2")

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityLog(BaseModel):
    event_id: int
    source: str
    message: str


# =========================
# AI / RULE BASED ANALYSIS
# =========================
def analyze_log(message: str):
    msg = message.lower()

    if "failed login" in msg or "invalid password" in msg:
        return "High", "Brute Force Attack"

    if "scan" in msg or "port" in msg:
        return "Medium", "Reconnaissance Activity"

    if "login successful" in msg:
        return "Low", "Normal Login"

    return "Low", "Unknown Activity"


# =========================
# ROOT
# =========================
@app.get("/")
def root():
    return {"status": "running"}


# =========================
# RECEIVE LOG + SAVE DB
# =========================
@app.post("/logs")
def receive_log(log: SecurityLog):
    severity, threat_type = analyze_log(log.message)

    db = SessionLocal()

    db_log = LogEntry(
        source=log.source,
        event_type=threat_type,
        severity=severity,
        description=log.message
    )

    db.add(db_log)
    db.commit()
    db.close()

    return {
        "status": "saved",
        "severity": severity,
        "threat_type": threat_type
    }


# =========================
# GET LOGS (IMPORTANT FOR STREAMLIT)
# =========================
@app.get("/logs")
def get_logs():
    db = SessionLocal()
    logs = db.query(LogEntry).order_by(LogEntry.id.desc()).all()
    db.close()

    return [
        {
            "ID": log.id,
            "Source": log.source,
            "Threat": log.event_type,
            "Severity": log.severity,
            "Description": log.description,
            "Time": str(log.timestamp)
        }
        for log in logs
    ]