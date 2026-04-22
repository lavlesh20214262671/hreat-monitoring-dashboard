from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Deque, Dict, List

import psutil

_LOGS_MAX = 200
_logs: Deque[Dict[str, str]] = deque(maxlen=_LOGS_MAX)
_logs_lock = Lock()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_log(message: str, level: str = "info") -> Dict[str, str]:
    entry = {"timestamp": _utc_timestamp(), "level": level, "message": message}
    with _logs_lock:
        _logs.appendleft(entry)
    return entry


def get_logs(limit: int = 50) -> List[Dict[str, str]]:
    safe_limit = max(1, min(limit, _LOGS_MAX))
    with _logs_lock:
        return list(_logs)[:safe_limit]


def get_system_metrics() -> Dict[str, float]:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": vm.percent,
        "disk_percent": disk.percent,
    }


add_log("Monitoring service initialized")
