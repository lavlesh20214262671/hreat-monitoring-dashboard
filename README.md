# SecureView — Threat Intelligence Dashboard
### Full-Stack Portfolio Project for Palo Alto Networks ASE Role

---

## 🏗️ Project Architecture

```
secureview/
├── backend/
│   ├── main.py          # FastAPI app — REST + WebSocket endpoints
│   ├── models.py        # Pydantic schemas (Alert, Endpoint, CVE, etc.)
│   ├── data_store.py    # In-memory data store with seeded threat data
│   ├── threat_engine.py # Real-time threat event simulator
│   └── requirements.txt
│
└── frontend/
    └── index.html       # Single-file dashboard (HTML + CSS + JS)
```

---

## ⚙️ Tech Stack

| Layer     | Technology             | Why                                      |
|-----------|------------------------|------------------------------------------|
| Backend   | **FastAPI** (Python)   | Async, modern, auto-generates OpenAPI    |
| Realtime  | **WebSocket**          | Live threat feed without polling         |
| Schemas   | **Pydantic v2**        | Type-safe request/response validation    |
| Server    | **Uvicorn**            | ASGI server for async FastAPI            |
| Frontend  | **Vanilla JS + CSS**   | Zero dependencies, fast, portable        |
| Fonts     | JetBrains Mono + Syne  | Monospace terminal feel                  |

---

## 🚀 Quick Start

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
python main.py
# Server starts at http://localhost:8000
```

### 2. Frontend

Open `frontend/index.html` in a browser.

The frontend auto-detects if the backend is running:
- **Backend running** → Fetches live data via REST + WebSocket
- **No backend** → Falls back to built-in Demo Mode automatically

---

## 📡 API Reference

All endpoints served at `http://localhost:8000`

### REST Endpoints

| Method | Path                                  | Description                  |
|--------|---------------------------------------|------------------------------|
| GET    | `/api/stats`                          | Live KPI statistics          |
| GET    | `/api/alerts`                         | Active alerts (filterable)   |
| GET    | `/api/alerts/{id}`                    | Single alert details         |
| POST   | `/api/alerts/{id}/action`             | Resolve / block / escalate   |
| GET    | `/api/endpoints`                      | XDR endpoint health          |
| GET    | `/api/vulnerabilities`                | CVE tracker                  |
| POST   | `/api/vulnerabilities/{cve}/patch`    | Trigger patch workflow       |
| GET    | `/api/traffic`                        | 24h network traffic data     |
| GET    | `/api/protocols`                      | SASE protocol breakdown      |
| GET    | `/api/logs`                           | Firewall/IDS event log       |
| GET    | `/api/geo-threats`                    | Geographic attack origins    |

### WebSocket

```
ws://localhost:8000/ws/live
```

**Server → Client message types:**
```json
{ "type": "snapshot",      "stats": {...}, "alerts": [...] }
{ "type": "stats_update",  "data": { "active_threats": 249, ... } }
{ "type": "log_entry",     "data": { "source_ip": "...", "action": "BLOCKED", ... } }
{ "type": "new_alert",     "data": { "id": "ALT-xxx", "severity": "critical", ... } }
{ "type": "geo_attack",    "data": { "country": "RU", "lat": 61.5, "lon": 105.3, ... } }
{ "type": "alert_update",  "alert_id": "ALT-001", "action": "resolved" }
{ "type": "patch_initiated","cve_id": "CVE-2024-3094", "playbook": "cortex-xsoar-patch-v2" }
```

**Client → Server:**
```json
{ "type": "ping" }
```

**Auto-docs:** http://localhost:8000/docs (Swagger UI)

---

## 🔐 Security Concepts Demonstrated

| Concept         | Implementation                                          |
|-----------------|----------------------------------------------------------|
| **XDR**         | Endpoint health grid with agent version tracking        |
| **SASE**        | Protocol analysis panel showing network traffic types   |
| **MITRE ATT&CK**| Every alert tagged with Tactic + Technique IDs          |
| **CVE / CVSS**  | Vulnerability tracker with CVSS scoring and patch flow  |
| **C2 Detection**| Cobalt Strike beacon alert with confidence score        |
| **Ransomware**  | LockBit signature alert with isolation response         |
| **Data Exfil**  | DNS tunneling detection (iodine signature)              |
| **Automation**  | Cortex XSOAR-style patch playbook triggering via API    |
| **Geo Threats** | Attack origin map (Russia, China, NK, Iran, etc.)       |

---

## 🎯 How to Talk About This in PAN Interviews

1. **Architecture:** "I designed a REST + WebSocket API that mirrors how SIEM platforms ingest and stream events in real-time."

2. **XDR:** "The endpoint panel simulates Cortex XDR telemetry — each endpoint reports CPU/memory usage and threats blocked by the agent."

3. **SASE:** "The protocol analysis panel reflects SASE visibility principles — knowing exactly what traffic traverses the network and classifying it by threat level."

4. **Automation:** "The patch workflow triggers a named XSOAR playbook via POST, which is how Cortex XSOAR orchestrates remediation in production."

5. **MITRE ATT&CK:** "Every alert is mapped to a Tactic and Technique — this is standard in PAN's Security Operating Platform for threat contextualization."

---

## 🗺️ Production Upgrade Path

| Component        | Demo Version          | Production Version              |
|------------------|-----------------------|---------------------------------|
| Database         | In-memory dict        | PostgreSQL + Elasticsearch      |
| Auth             | None                  | OAuth2 + JWT                    |
| Threat Feeds     | Simulated             | AutoFocus / XSOAR / Kafka       |
| Endpoints        | Static seed data      | Cortex XDR API                  |
| Patch Workflow   | Mock POST             | Cortex XSOAR Playbook API       |
| Deployment       | `python main.py`      | Docker + Kubernetes             |
| Frontend         | Single HTML file      | React + TypeScript              |

---

*Built by [Your Name] — Portfolio Project, 2024*
*Targeting: Associate Systems Engineer (CAMP) — Palo Alto Networks*
