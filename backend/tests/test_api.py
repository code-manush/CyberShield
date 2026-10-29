import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import Base, engine


@pytest.fixture(scope="module")
def client():
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c


def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ["HEALTHY", "DEGRADED"]
    assert data["database_connected"] is True


def test_system_status(client):
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    assert "system" in data
    assert "monitoring" in data
    assert "prevention" in data


def test_monitoring_status(client):
    res = client.get("/api/monitoring/status")
    assert res.status_code == 200
    data = res.json()
    assert "is_running" in data
    assert "available_interfaces" in data


def test_ml_metrics(client):
    res = client.get("/api/ml/metrics")
    assert res.status_code == 200
    data = res.json()
    assert "is_trained" in data
    assert "accuracy" in data
    assert "confusion_matrix" in data


def test_auth_login_service(client):
    # Valid login test with admin account
    res_valid = client.post("/api/auth/login", json={"username": "admin", "password": "AdminSecret2026!"})
    assert res_valid.status_code == 200
    assert res_valid.json()["success"] is True

    # Invalid login test
    res_invalid = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword123"})
    assert res_invalid.status_code == 200
    assert res_invalid.json()["success"] is False


def test_prevention_block_unblock_api(client):
    # Try blocking an IP
    block_res = client.post("/api/prevention/block-ip", json={
        "ip_address": "198.51.100.22",
        "reason": "Test manual administrative block",
        "duration_seconds": 60
    })
    assert block_res.status_code == 200

    # Verify IP appears in blocked list
    list_res = client.get("/api/prevention/blocked-ips")
    assert list_res.status_code == 200
    blocked_ips = [b["ip_address"] for b in list_res.json()]
    assert "198.51.100.22" in blocked_ips

    # Unblock IP
    unblock_res = client.post("/api/prevention/unblock-ip", json={
        "ip_address": "198.51.100.22"
    })
    assert unblock_res.status_code == 200


def test_allowlist_blocking_rejected(client):
    res = client.post("/api/prevention/block-ip", json={
        "ip_address": "127.0.0.1",
        "reason": "Accidental loopback block"
    })
    assert res.status_code == 400
    assert "allowlist" in res.json()["detail"].lower()


def test_simulation_status_and_control(client):
    res = client.get("/api/simulation/status")
    assert res.status_code == 200
    data = res.json()
    assert "is_attacking" in data
    assert "current_step" in data

    # Test stopping simulation when idle
    stop_res = client.post("/api/simulation/stop")
    assert stop_res.status_code == 200
