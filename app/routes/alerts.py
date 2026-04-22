from fastapi import APIRouter

from ..data_handler import get_system_metrics
from ..threat_simulation import generate_alerts

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("")
def read_alerts():
    metrics = get_system_metrics()
    return {
        "alerts": generate_alerts(
            cpu_percent=metrics["cpu_percent"],
            memory_percent=metrics["memory_percent"],
        )
    }
