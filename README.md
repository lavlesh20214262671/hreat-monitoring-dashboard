# hreat-monitoring-dashboard

Full-stack real-time threat monitoring dashboard with a Python FastAPI backend and frontend UI for system metrics, alerts, and logs.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## API endpoints

- `GET /api/metrics` - CPU, memory, and disk usage
- `GET /api/alerts` - simulated threat alerts from current metrics
- `GET /api/logs?limit=50` - recent service logs
