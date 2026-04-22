from __future__ import annotations

from datetime import datetime, timezone
from random import choice
from typing import Dict, List

from .data_handler import add_log


_MESSAGES = [
    "Brute-force login pattern detected",
    "Unexpected port scanning activity observed",
    "Repeated failed API authentication attempts",
]


def generate_alerts(cpu_percent: float, memory_percent: float) -> List[Dict[str, str]]:
    alerts: List[Dict[str, str]] = []

    if cpu_percent > 85:
        alerts.append(_make_alert("high", "CPU usage exceeded 85%"))
    if memory_percent > 90:
        alerts.append(_make_alert("critical", "Memory usage exceeded 90%"))
    if cpu_percent > 70 and memory_percent > 75:
        alerts.append(_make_alert("medium", choice(_MESSAGES)))

    for alert in alerts:
        add_log(f"ALERT [{alert['severity']}]: {alert['message']}", level="warning")

    return alerts


def _make_alert(severity: str, message: str) -> Dict[str, str]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "message": message,
    }
