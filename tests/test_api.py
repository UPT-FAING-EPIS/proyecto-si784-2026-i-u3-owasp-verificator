import os

os.environ["APP_ENV"] = "test"

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import scan_store

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_store_between_tests():
    scan_store.clear()
    yield
    scan_store.clear()


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_api_code_flow():
    payload = {
        "target_type": "code",
        "target_value": "password = 'secret'\nprint(eval(data))",
    }
    response = client.post("/analyze/api", json=payload)
    assert response.status_code == 200

    scan = response.json()
    assert scan["target_type"] == "code"
    assert scan["score"] <= 100
    assert len(scan["findings"]) >= 1

    report_response = client.get(f"/reports/api/{scan['id']}")
    assert report_response.status_code == 200
    assert report_response.json()["id"] == scan["id"]
