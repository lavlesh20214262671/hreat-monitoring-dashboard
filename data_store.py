"""
SecureView - In-Memory Data Store
Simulates a real database with seeded cybersecurity data.
In production this would connect to PostgreSQL + Elasticsearch.
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from models import (
    Alert, Endpoint, Vulnerability, LogEntry,
    ThreatStats, NetworkTraffic, ProtocolData,
    SeverityLevel, EndpointStatus, VulnStatus, AlertStatus
)


class DataStore:
    _alerts: List[Alert] = []
    _endpoints: List[Endpoint] = []
    _vulnerabilities: List[Vulnerability] = []
    _logs: List[LogEntry] = []
    _traffic: List[NetworkTraffic] = []
    _protocols: List[ProtocolData] = []
    _stats: ThreatStats = None
    _geo_threats: List[Dict] = []

    # ── Seed ──────────────────────────────────────────────────────────────────
    @classmethod
    def seed(cls):
        cls._seed_alerts()
        cls._seed_endpoints()
        cls._seed_vulnerabilities()
        cls._seed_logs()
        cls._seed_traffic()
        cls._seed_protocols()
        cls._seed_stats()
        cls._seed_geo_threats()

    @classmethod
    def _seed_alerts(cls):
        now = datetime.utcnow()
        data = [
            ("ALT-001", "Brute Force — SSH", "185.220.101.47", "10.0.0.12",
             SeverityLevel.critical, "Credential Attack", "SSH", "RU", 8420,
             AlertStatus.blocked, "TA0006", "T1110.001", 0.96,
             "Sustained SSH brute-force from known Tor exit node. 8,420 failed auth attempts detected. Source IP matches IOC feed #TOR-EXIT-47."),

            ("ALT-002", "C2 Beacon Detected", "91.109.6.14", "10.0.1.88",
             SeverityLevel.critical, "Malware C2", "HTTPS", "CN", 124,
             AlertStatus.quarantined, "TA0011", "T1071.001", 0.94,
             "Endpoint 10.0.1.88 beaconing to known C2 server every 60s. Traffic matches Cobalt Strike default malleable profile. Host quarantined pending forensics."),

            ("ALT-003", "SQL Injection Attempt", "45.12.53.11", "db-prod-01",
             SeverityLevel.high, "Web Attack", "HTTP", "US", 312,
             AlertStatus.blocked, "TA0001", "T1190", 0.91,
             "UNION-based SQL injection payloads detected targeting /api/users endpoint. 312 malformed requests in 4 minutes. WAF rule SQ-4422 triggered."),

            ("ALT-004", "Lateral Movement Detected", "10.0.0.45", "10.0.0.0/24",
             SeverityLevel.critical, "Insider Threat", "SMB", "INT", 55,
             AlertStatus.investigating, "TA0008", "T1021.002", 0.88,
             "Workstation WS-DEV-003 scanning internal /24 subnet via SMB. Possible Pass-the-Hash attack. User account flagged for unusual access pattern."),

            ("ALT-005", "DNS Tunneling — Data Exfil", "203.0.113.22", "dns-01",
             SeverityLevel.high, "Data Exfiltration", "DNS", "BR", 2100,
             AlertStatus.blocked, "TA0010", "T1048.003", 0.87,
             "Anomalously long DNS TXT queries detected (avg 180 chars). Entropy analysis indicates base64-encoded data. Matches known iodine tunneling signatures."),

            ("ALT-006", "Ransomware Signature Match", "10.0.0.99", "file-server-02",
             SeverityLevel.critical, "Ransomware", "SMB", "INT", 1,
             AlertStatus.quarantined, "TA0040", "T1486", 0.99,
             "LockBit 3.0 ransomware signature detected on SRV-FILE-02. File encryption activity halted. Host isolated. 14 files encrypted before containment."),

            ("ALT-007", "NMAP Port Scan", "198.51.100.5", "10.0.0.0/24",
             SeverityLevel.medium, "Reconnaissance", "TCP", "DE", 65535,
             AlertStatus.blocked, "TA0043", "T1595.001", 0.82,
             "Full TCP SYN scan across /24 range. 65,535 ports probed in 8 minutes. Source fingerprint matches NMAP OS detection mode."),
        ]
        cls._alerts = []
        for i, row in enumerate(data):
            cls._alerts.append(Alert(
                id=row[0], title=row[1], source_ip=row[2], destination=row[3],
                severity=row[4], threat_type=row[5], protocol=row[6],
                country=row[7], attempts=row[8], status=row[9],
                timestamp=datetime.utcnow() - timedelta(minutes=i * 4 + 2),
                mitre_tactic=row[10], mitre_technique=row[11],
                confidence=row[12], description=row[13]
            ))

    @classmethod
    def _seed_endpoints(cls):
        data = [
            ("EP-001", "WS-PROD-001", EndpointStatus.ok,    "Windows 11 Pro", "10.0.0.101", "6.1.2", 142, 12.4, 34.2),
            ("EP-002", "SRV-DB-01",   EndpointStatus.warn,  "RHEL 9.2",       "10.0.0.52",  "6.1.1", 87,  78.3, 62.1),
            ("EP-003", "WS-EXEC-007", EndpointStatus.ok,    "macOS 14.3",     "10.0.1.7",   "6.1.2", 23,  8.1,  41.0),
            ("EP-004", "SRV-WEB-02",  EndpointStatus.critical,"Ubuntu 22.04", "10.0.0.88",  "6.0.9", 891, 94.2, 88.7),
            ("EP-005", "WS-DEV-012",  EndpointStatus.ok,    "Windows 11 Pro", "10.0.1.45",  "6.1.2", 56,  22.0, 55.3),
            ("EP-006", "SRV-FILE-03", EndpointStatus.warn,  "Windows Server", "10.0.0.99",  "6.1.0", 234, 45.6, 71.2),
            ("EP-007", "WS-HR-004",   EndpointStatus.ok,    "Windows 10",     "10.0.2.14",  "6.1.2", 12,  5.3,  28.9),
            ("EP-008", "SRV-AUTH-01", EndpointStatus.ok,    "RHEL 9.2",       "10.0.0.10",  "6.1.2", 445, 31.2, 44.1),
        ]
        cls._endpoints = [
            Endpoint(
                id=r[0], name=r[1], status=r[2], os=r[3], ip=r[4],
                last_seen=datetime.utcnow() - timedelta(seconds=random.randint(0, 300)),
                agent_version=r[5], threats_blocked=r[6],
                cpu_usage=r[7], memory_usage=r[8]
            ) for r in data
        ]

    @classmethod
    def _seed_vulnerabilities(cls):
        data = [
            ("CVE-2024-3094",  "XZ Utils Backdoor — Remote Code Execution via liblzma",         10.0, True,  True,  VulnStatus.open),
            ("CVE-2024-21762", "Fortinet FortiOS SSL-VPN RCE — Out-of-bound Write",              9.6,  True,  True,  VulnStatus.open),
            ("CVE-2024-1709",  "ConnectWise ScreenConnect Auth Bypass",                          10.0, True,  True,  VulnStatus.patching),
            ("CVE-2023-46805", "Ivanti Connect Secure Policy Bypass + Auth Bypass Chain",        8.2,  True,  True,  VulnStatus.open),
            ("CVE-2024-4577",  "PHP CGI Windows Argument Injection — RCE",                       9.8,  True,  False, VulnStatus.open),
            ("CVE-2024-6387",  "OpenSSH regreSSHion — Remote Code Execution (glibc)",            8.1,  True,  False, VulnStatus.patching),
            ("CVE-2024-23897", "Jenkins CLI Arbitrary File Read — Path Traversal",               9.8,  True,  True,  VulnStatus.patched),
            ("CVE-2024-27198", "JetBrains TeamCity Auth Bypass — Full Admin Access",             9.8,  True,  True,  VulnStatus.patched),
        ]
        cls._vulnerabilities = []
        for row in data:
            sev = SeverityLevel.critical if row[2] >= 9.0 else (
                  SeverityLevel.high if row[2] >= 7.0 else SeverityLevel.medium)
            cls._vulnerabilities.append(Vulnerability(
                cve_id=row[0], description=row[1], cvss_score=row[2],
                severity=sev, affected_assets=random.randint(1, 24),
                status=row[5],
                published_date=datetime.utcnow() - timedelta(days=random.randint(5, 120)),
                patch_available=row[3], exploit_available=row[4]
            ))

    @classmethod
    def _seed_logs(cls):
        templates = [
            ("10.0.1.45",      "firewall-01",   "BLOCKED", "Malware download blocked — md5:a3f9c12",    "HTTP",  SeverityLevel.high),
            ("185.220.101.47", "10.0.0.12",     "BLOCKED", "SSH brute force — 1,024 attempts",          "SSH",   SeverityLevel.critical),
            ("10.0.0.88",      "auth.corp.lan",  "ALLOWED", "Office365 authentication success",          "HTTPS", SeverityLevel.info),
            ("10.0.1.99",      "91.109.6.14",   "BLOCKED", "C2 callback blocked",                       "HTTPS", SeverityLevel.critical),
            ("198.51.100.5",   "10.0.0.0/24",   "ALERT",   "Port scan — 65k ports in 8 minutes",        "TCP",   SeverityLevel.medium),
            ("10.0.0.12",      "vpn.corp.lan",  "ALLOWED", "VPN tunnel established — user: jsmith",     "IPSec", SeverityLevel.info),
            ("10.0.0.45",      "10.0.0.0/24",   "ALERT",   "Lateral movement via SMB detected",         "SMB",   SeverityLevel.critical),
            ("203.0.113.22",   "dns-01",        "BLOCKED", "DNS tunneling — data exfiltration attempt",  "DNS",   SeverityLevel.high),
            ("10.0.1.7",       "backup.corp",   "ALLOWED", "Cloud backup completed — 2.4 GB",           "HTTPS", SeverityLevel.info),
            ("45.12.53.11",    "db-prod-01",    "BLOCKED", "SQL injection payload detected",             "HTTP",  SeverityLevel.high),
            ("10.0.2.14",      "hr.corp.lan",   "ALLOWED", "File access: payroll_2024.xlsx",            "SMB",   SeverityLevel.info),
            ("10.0.0.99",      "file-server-02","ALERT",   "Ransomware behaviour: mass file encryption", "SMB",   SeverityLevel.critical),
        ]
        cls._logs = []
        for i, t in enumerate(templates):
            cls._logs.append(LogEntry(
                id=f"LOG-{str(uuid.uuid4())[:8].upper()}",
                timestamp=datetime.utcnow() - timedelta(seconds=i * 18),
                source_ip=t[0], destination=t[1], action=t[2],
                message=t[3], protocol=t[4], severity=t[5],
                rule_id=f"RULE-{random.randint(1000,9999)}"
            ))

    @classmethod
    def _seed_traffic(cls):
        hourly = [
            (0,"00:00",820,340,12400,280,0.12), (1,"01:00",640,210,9800,140,0.09),
            (2,"02:00",510,180,8200,98,0.08),   (3,"03:00",490,150,7900,112,0.07),
            (4,"04:00",530,200,8600,145,0.09),  (5,"05:00",720,280,11000,210,0.11),
            (6,"06:00",1100,450,16500,340,0.14),(7,"07:00",1850,780,28000,520,0.18),
            (8,"08:00",2800,1100,42000,780,0.22),(9,"09:00",3200,1400,48000,920,0.25),
            (10,"10:00",3500,1600,53000,1100,0.28),(11,"11:00",3800,1700,57000,1240,0.31),
            (12,"12:00",3600,1650,54000,1180,0.29),(13,"13:00",3400,1550,51000,1050,0.27),
            (14,"14:00",3900,1800,58000,1320,0.33),(15,"15:00",4200,1950,63000,1580,0.38),
            (16,"16:00",4800,2200,72000,2100,0.44),(17,"17:00",5200,2400,78000,2800,0.52),
            (18,"18:00",4600,2100,69000,2400,0.48),(19,"19:00",3800,1700,57000,1900,0.41),
            (20,"20:00",3200,1400,48000,1600,0.35),(21,"21:00",2600,1100,39000,1200,0.30),
            (22,"22:00",1900,800,28500,850,0.22),(23,"23:00",1200,520,18000,480,0.16),
        ]
        cls._traffic = [
            NetworkTraffic(hour=r[0], label=r[1], bytes_in=r[2]*1024,
                           bytes_out=r[3]*1024, packets=r[4],
                           blocked_packets=r[5], threat_score=r[6])
            for r in hourly
        ]

    @classmethod
    def _seed_protocols(cls):
        cls._protocols = [
            ProtocolData(protocol="HTTPS", percentage=38.2, threat_percentage=12.4, bytes_total=1_240_000_000, color="#00d2ff"),
            ProtocolData(protocol="HTTP",  percentage=22.1, threat_percentage=31.8, bytes_total=718_000_000,  color="#ff4560"),
            ProtocolData(protocol="DNS",   percentage=14.5, threat_percentage=8.2,  bytes_total=471_000_000,  color="#00ff88"),
            ProtocolData(protocol="SSH",   percentage=9.8,  threat_percentage=44.1, bytes_total=318_000_000,  color="#ffb300"),
            ProtocolData(protocol="SMB",   percentage=8.3,  threat_percentage=28.6, bytes_total=270_000_000,  color="#a855f7"),
            ProtocolData(protocol="RDP",   percentage=4.2,  threat_percentage=19.3, bytes_total=136_000_000,  color="#f97316"),
            ProtocolData(protocol="Other", percentage=2.9,  threat_percentage=5.1,  bytes_total=94_000_000,   color="#64748b"),
        ]

    @classmethod
    def _seed_stats(cls):
        cls._stats = ThreatStats(
            active_threats=247, blocked_attacks=14218,
            endpoints_monitored=3841, open_vulnerabilities=89,
            cloud_assets=612, attacks_per_minute=142,
            threat_level="HIGH",
            firewall_status="active", ids_status="online",
            siem_status="connected", cloud_waf_status="degraded",
            last_updated=datetime.utcnow()
        )

    @classmethod
    def _seed_geo_threats(cls):
        cls._geo_threats = [
            {"country": "Russia",        "country_code": "RU", "lat": 61.5,   "lon": 105.3,  "attacks": 3842, "type": "Brute Force",     "active": True},
            {"country": "China",         "country_code": "CN", "lat": 35.9,   "lon": 104.2,  "attacks": 2941, "type": "APT / Malware",   "active": True},
            {"country": "North Korea",   "country_code": "KP", "lat": 40.3,   "lon": 127.5,  "attacks": 1205, "type": "Ransomware",      "active": True},
            {"country": "Brazil",        "country_code": "BR", "lat": -14.2,  "lon": -51.9,  "attacks": 892,  "type": "Data Exfil",      "active": True},
            {"country": "Germany",       "country_code": "DE", "lat": 51.2,   "lon": 10.5,   "attacks": 445,  "type": "Reconnaissance",  "active": False},
            {"country": "United States", "country_code": "US", "lat": 37.1,   "lon": -95.7,  "attacks": 1120, "type": "Web Attack",      "active": True},
            {"country": "Iran",          "country_code": "IR", "lat": 32.4,   "lon": 53.7,   "attacks": 678,  "type": "DDoS",            "active": False},
            {"country": "Netherlands",   "country_code": "NL", "lat": 52.1,   "lon": 5.3,    "attacks": 334,  "type": "C2 Hosting",      "active": True},
        ]

    # ── Getters ───────────────────────────────────────────────────────────────
    @classmethod
    def get_alerts(cls) -> List[Alert]:
        return sorted(cls._alerts, key=lambda a: a.timestamp, reverse=True)

    @classmethod
    def get_alert(cls, alert_id: str) -> Optional[Alert]:
        return next((a for a in cls._alerts if a.id == alert_id), None)

    @classmethod
    def update_alert_status(cls, alert_id: str, action: str) -> str:
        for a in cls._alerts:
            if a.id == alert_id:
                mapping = {
                    "resolve":    AlertStatus.resolved,
                    "block":      AlertStatus.blocked,
                    "escalate":   AlertStatus.escalated,
                    "quarantine": AlertStatus.quarantined,
                }
                a.status = mapping.get(action, a.status)
                return a.status
        return "not_found"

    @classmethod
    def get_endpoints(cls) -> List[Endpoint]:
        return cls._endpoints

    @classmethod
    def get_vulnerabilities(cls) -> List[Vulnerability]:
        return sorted(cls._vulnerabilities, key=lambda v: v.cvss_score, reverse=True)

    @classmethod
    def patch_vulnerability(cls, cve_id: str) -> str:
        for v in cls._vulnerabilities:
            if v.cve_id == cve_id:
                v.status = VulnStatus.patching
                return "patching"
        return "not_found"

    @classmethod
    def get_logs(cls, limit: int = 50) -> List[LogEntry]:
        return sorted(cls._logs, key=lambda l: l.timestamp, reverse=True)[:limit]

    @classmethod
    def add_log(cls, entry: LogEntry):
        cls._logs.insert(0, entry)
        if len(cls._logs) > 500:
            cls._logs.pop()

    @classmethod
    def get_traffic_data(cls) -> List[NetworkTraffic]:
        return cls._traffic

    @classmethod
    def get_protocol_data(cls) -> List[ProtocolData]:
        return cls._protocols

    @classmethod
    def get_stats(cls) -> ThreatStats:
        # Simulate live fluctuation
        s = cls._stats
        s.active_threats += random.randint(-2, 4)
        s.attacks_per_minute = 120 + random.randint(0, 80)
        s.blocked_attacks += random.randint(0, 6)
        s.last_updated = datetime.utcnow()
        return s

    @classmethod
    def get_geo_threats(cls) -> List[Dict]:
        return cls._geo_threats

    @classmethod
    def add_alert(cls, alert: Alert):
        cls._alerts.insert(0, alert)
        cls._stats.active_threats += 1
