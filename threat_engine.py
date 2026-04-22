"""
SecureView - Threat Engine
Simulates real-time threat events and pushes to WebSocket clients.
In production this would consume from Kafka/Splunk/SIEM feeds.
"""

import asyncio
import random
import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from models import Alert, LogEntry, SeverityLevel, AlertStatus
from data_store import DataStore


class ThreatEngine:
    """
    Generates realistic cybersecurity events at randomized intervals.
    Simulates: new alerts, log entries, KPI fluctuations, geo attacks.
    """

    ATTACK_TYPES = [
        ("Brute Force — SSH",         "Credential Attack", "SSH",   SeverityLevel.critical, "TA0006", "T1110.001"),
        ("SQL Injection Attempt",      "Web Attack",        "HTTP",  SeverityLevel.high,     "TA0001", "T1190"),
        ("XSS Payload Detected",       "Web Attack",        "HTTP",  SeverityLevel.medium,   "TA0001", "T1059"),
        ("Phishing Link Clicked",      "Phishing",          "HTTPS", SeverityLevel.high,     "TA0001", "T1566.002"),
        ("Ransomware Behaviour",       "Ransomware",        "SMB",   SeverityLevel.critical, "TA0040", "T1486"),
        ("Data Exfiltration — DNS",    "Data Exfil",        "DNS",   SeverityLevel.high,     "TA0010", "T1048.003"),
        ("Port Scan Detected",         "Reconnaissance",    "TCP",   SeverityLevel.medium,   "TA0043", "T1595"),
        ("C2 Beacon",                  "Malware C2",        "HTTPS", SeverityLevel.critical, "TA0011", "T1071.001"),
        ("Lateral Movement — SMB",     "Insider Threat",    "SMB",   SeverityLevel.critical, "TA0008", "T1021.002"),
        ("Credential Dump Attempt",    "Credential Access", "LSASS", SeverityLevel.critical, "TA0006", "T1003.001"),
        ("DDoS — SYN Flood",           "DDoS",              "TCP",   SeverityLevel.high,     "TA0040", "T1498"),
        ("Log Tampering Detected",     "Defense Evasion",   "N/A",   SeverityLevel.high,     "TA0005", "T1070"),
    ]

    LOG_TEMPLATES = [
        ("BLOCKED", "Malware payload blocked at perimeter",          SeverityLevel.high),
        ("BLOCKED", "Outbound C2 connection terminated",             SeverityLevel.critical),
        ("ALLOWED", "User VPN auth success",                         SeverityLevel.info),
        ("BLOCKED", "SQL injection pattern matched — WAF rule hit",  SeverityLevel.high),
        ("ALLOWED", "Cloud sync completed",                          SeverityLevel.info),
        ("ALERT",   "Anomalous privilege escalation detected",       SeverityLevel.critical),
        ("BLOCKED", "Known botnet IP blocked at edge firewall",      SeverityLevel.medium),
        ("ALLOWED", "LDAP auth success — user provisioned",         SeverityLevel.info),
        ("ALERT",   "Unusual outbound bandwidth spike — 4.2 GB/hr", SeverityLevel.high),
        ("BLOCKED", "Exploit kit payload dropped — agent blocked",   SeverityLevel.critical),
    ]

    SOURCE_IPS = [
        "185.220.101.47", "91.109.6.14", "45.12.53.11", "198.51.100.5",
        "203.0.113.22", "192.0.2.88", "198.18.0.44", "100.64.0.12",
        "10.0.0.45", "10.0.1.99", "10.0.2.14",  # internal IPs (insider threat)
        "77.88.55.77", "8.8.4.4", "1.1.1.1",    # spoofed common IPs
    ]

    DEST_HOSTS = [
        "10.0.0.12", "10.0.1.88", "db-prod-01", "file-server-02",
        "auth-server-01", "10.0.0.0/24", "dns-01", "web-prod-02",
    ]

    COUNTRIES = ["RU", "CN", "KP", "US", "DE", "BR", "IR", "NL", "UA", "RO"]

    def __init__(self):
        self._event_counter = 0
        self._last_alert_time = datetime.utcnow()

    def generate_event(self) -> Optional[Dict[str, Any]]:
        """Generate a random live event. Returns None sometimes to vary rate."""
        self._event_counter += 1

        roll = random.random()

        if roll < 0.35:
            return self._make_log_event()
        elif roll < 0.55:
            return self._make_stat_update()
        elif roll < 0.68:
            return self._make_new_alert()
        elif roll < 0.78:
            return self._make_geo_attack()
        else:
            return None  # Quiet moment

    def _make_log_event(self) -> Dict:
        template = random.choice(self.LOG_TEMPLATES)
        src = random.choice(self.SOURCE_IPS)
        dst = random.choice(self.DEST_HOSTS)

        entry = LogEntry(
            id=f"LOG-{str(uuid.uuid4())[:8].upper()}",
            timestamp=datetime.utcnow(),
            source_ip=src,
            destination=dst,
            action=template[0],
            message=template[1],
            protocol=random.choice(["HTTP", "HTTPS", "SSH", "DNS", "SMB", "TCP"]),
            severity=template[2],
            rule_id=f"RULE-{random.randint(1000, 9999)}"
        )
        DataStore.add_log(entry)
        return {
            "type": "log_entry",
            "data": entry.model_dump(mode="json")
        }

    def _make_new_alert(self) -> Dict:
        attack = random.choice(self.ATTACK_TYPES)
        alert = Alert(
            id=f"ALT-{str(uuid.uuid4())[:6].upper()}",
            title=attack[0],
            source_ip=random.choice(self.SOURCE_IPS),
            destination=random.choice(self.DEST_HOSTS),
            severity=attack[3],
            threat_type=attack[1],
            protocol=attack[2],
            country=random.choice(self.COUNTRIES),
            attempts=random.randint(1, 10000),
            status=AlertStatus.active,
            timestamp=datetime.utcnow(),
            mitre_tactic=attack[4],
            mitre_technique=attack[5],
            confidence=round(random.uniform(0.72, 0.99), 2),
            description=f"Auto-generated: {attack[0]} detected by ML engine."
        )
        DataStore.add_alert(alert)
        return {
            "type": "new_alert",
            "data": alert.model_dump(mode="json")
        }

    def _make_stat_update(self) -> Dict:
        stats = DataStore.get_stats()
        return {
            "type": "stats_update",
            "data": {
                "active_threats": stats.active_threats,
                "blocked_attacks": stats.blocked_attacks,
                "attacks_per_minute": stats.attacks_per_minute,
                "threat_level": stats.threat_level,
                "timestamp": datetime.utcnow().isoformat()
            }
        }

    def _make_geo_attack(self) -> Dict:
        geo = random.choice(DataStore.get_geo_threats())
        return {
            "type": "geo_attack",
            "data": {
                "country": geo["country"],
                "country_code": geo["country_code"],
                "lat": geo["lat"] + random.uniform(-2, 2),
                "lon": geo["lon"] + random.uniform(-2, 2),
                "attack_type": geo["type"],
                "intensity": random.randint(1, 10),
                "timestamp": datetime.utcnow().isoformat()
            }
        }

    async def simulate_loop(self):
        """Background coroutine — runs forever generating events."""
        while True:
            await asyncio.sleep(random.uniform(1.5, 3.5))
            # Events are generated on-demand via generate_event() in WS handler
