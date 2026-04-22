from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_metrics_endpoint_has_required_fields():
    response = client.get('/api/metrics')
    assert response.status_code == 200
    data = response.json()
    assert {'cpu_percent', 'memory_percent', 'disk_percent'}.issubset(data.keys())


def test_alerts_endpoint_returns_alerts_key():
    response = client.get('/api/alerts')
    assert response.status_code == 200
    data = response.json()
    assert 'alerts' in data
    assert isinstance(data['alerts'], list)


def test_logs_endpoint_limit_validation_and_payload():
    response = client.get('/api/logs?limit=5')
    assert response.status_code == 200
    data = response.json()
    assert 'logs' in data
    assert isinstance(data['logs'], list)
    assert len(data['logs']) <= 5

    invalid = client.get('/api/logs?limit=0')
    assert invalid.status_code == 422
