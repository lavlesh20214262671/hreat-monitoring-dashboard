from fastapi import APIRouter

from ..data_handler import get_system_metrics

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("")
def read_metrics():
    return get_system_metrics()
