from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import SessionLocal, engine
from models import Base, LegoSet
from schemas import SetCreate, SetUpdate, SetOut

app = FastAPI(title="Activity 5 CRUD API - LEGO Sets")

import time
from sqlalchemy.exc import OperationalError

@app.on_event("startup")
def on_startup():
    # Wait for Postgres container to be ready, then create tables
    for _ in range(30):  # up to ~30 seconds
        try:
            Base.metadata.create_all(bind=engine)
            return
        except OperationalError:
            time.sleep(1)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/sets/", response_model=SetOut, status_code=status.HTTP_201_CREATED)
def create_set(payload: SetCreate, db: Session = Depends(get_db)):
    obj = LegoSet(**payload.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj

@app.get("/sets/", response_model=list[SetOut])
def list_sets(db: Session = Depends(get_db)):
    return db.query(LegoSet).order_by(LegoSet.id).all()

@app.get("/sets/{set_id}", response_model=SetOut)
def read_set(set_id: int, db: Session = Depends(get_db)):
    obj = db.query(LegoSet).filter(LegoSet.id == set_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Set not found")
    return obj

@app.put("/sets/{set_id}", response_model=SetOut)
def update_set(set_id: int, payload: SetUpdate, db: Session = Depends(get_db)):
    obj = db.query(LegoSet).filter(LegoSet.id == set_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Set not found")

    updates = payload.model_dump(exclude_unset=True)
    for k, v in updates.items():
        setattr(obj, k, v)

    db.commit()
    db.refresh(obj)
    return obj

@app.delete("/sets/{set_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_set(set_id: int, db: Session = Depends(get_db)):
    obj = db.query(LegoSet).filter(LegoSet.id == set_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Set not found")
    db.delete(obj)
    db.commit()
    return
