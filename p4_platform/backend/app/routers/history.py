from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..database import get_db, iso_utc
from ..models import History
from ..schemas import HistoryCreate, HistoryOut
from ..security import get_current_claims, require_role

router = APIRouter(prefix="/history", tags=["history"])


def _end_of_day(value: str) -> str:
    # A bare date (YYYY-MM-DD) should include the whole day.
    return f"{value}T23:59:59.999Z" if len(value) == 10 else value


@router.post("", response_model=HistoryOut, status_code=status.HTTP_201_CREATED)
def create_history(
    body: HistoryCreate,
    db: Session = Depends(get_db),
    claims: dict = Depends(get_current_claims),
):
    entry = History(
        ts=iso_utc(),
        user=claims["sub"],
        module=body.module,
        action=body.action,
        ref_id=body.ref_id,
        summary=body.summary,
    )
    db.add(entry)
    db.commit()
    return entry


@router.get("", response_model=list[HistoryOut])
def list_history(
    module: str | None = None,
    from_date: str | None = Query(None, description="ISO 8601 UTC, inclusive"),
    to_date: str | None = Query(None, description="ISO 8601 UTC, inclusive"),
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
    _: dict = Depends(require_role(["admin", "analyst"])),
):
    q = db.query(History)
    if module:
        q = q.filter(History.module == module)
    if from_date:
        q = q.filter(History.ts >= from_date)
    if to_date:
        q = q.filter(History.ts <= _end_of_day(to_date))
    return q.order_by(History.ts.desc(), History.id.desc()).limit(limit).all()
