from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.crud import list_history
from app.db.session import get_db


router = APIRouter()


@router.get("/history")
def get_prediction_history(limit: int = 10, db: Session = Depends(get_db)):
    try:
        return list_history(db, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB query failed: {type(e).__name__}: {e}")

