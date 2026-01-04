import os, json
from sqlalchemy.orm import Session
from datetime import datetime
from .db import SessionLocal, Base, engine
from .models import Alert

Base.metadata.create_all(bind=engine)

def run(seed_path: str):
    db: Session = SessionLocal()
    try:
        with open(seed_path, "r", encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                # ensure ts parsed by sqlalchemy via datetime
                obj["ts"] = datetime.fromisoformat(obj["ts"].replace("Z",""))
                db.add(Alert(**obj))
        db.commit()
        print("Seeded alerts.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_path = os.getenv("SEED_PATH", "../../sample_data/alerts.jsonl")
    run(seed_path)
