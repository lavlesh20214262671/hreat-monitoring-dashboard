from fastapi import APIRouter, Query

from ..data_handler import get_logs

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def read_logs(limit: int = Query(default=50, ge=1, le=200)):
    return {"logs": get_logs(limit=limit)}
