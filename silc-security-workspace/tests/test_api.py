from io import BytesIO
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from src.api import app, DEFAULT_EVENTS, UPLOADS


@pytest.fixture
def client():
    UPLOADS.clear()
    with TestClient(app) as client:
        yield client


def csv_payload(**changes):
    frame = pd.read_csv(DEFAULT_EVENTS, keep_default_na=False).head(2)
    for key, value in changes.items():
        frame[key] = value
    return frame.to_csv(index=False).encode()


def test_demo_and_evidence(client):
    data = client.get("/api/analysis").json()
    assert data["events_analyzed"] == 11000
    assert data["alerts_generated"] == 10
    assert data["severity_counts"] == {"Critical": 1, "High": 8, "Medium": 1, "Low": 0}
    evidence = client.get("/api/evidence/" + data["alerts"][0]["alert_id"]).json()
    assert evidence["total"] == 85
    assert len(evidence["events"]) == 85


def test_frontend_assets(client):
    assert client.get("/").status_code == 200
    assert "SILC" in client.get("/").text
    assert client.get("/assets/workspace.js").status_code == 200
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/styles.css").status_code == 200
    assert client.get("/.env").status_code == 404


def test_upload_and_isolation(client):
    with DEFAULT_EVENTS.open("rb") as stream:
        result = client.post("/api/analyze-file", files={"file": ("test.csv", stream, "text/csv")})
    assert result.status_code == 200
    data = result.json()
    assert not data["synthetic"]
    assert data["analysis_id"] != "sample"
    body = {"analysis_id": data["analysis_id"], "alert_ids": [data["alerts"][0]["alert_id"]], "provider": "offline"}
    brief = client.post("/api/ai-summary", json=body)
    assert brief.status_code == 200
    assert not brief.json()["is_ai"]
    assert data["alerts"][0]["alert_id"] in brief.json()["summary"]
    assert client.get("/api/analysis").json()["synthetic"]
    assert "provenance not independently verified" in client.get("/api/report?analysis_id="+data["analysis_id"]).text


@pytest.mark.parametrize("payload", [
    b"x,y\n1,2", b"",
    csv_payload(source_ip="invalid"),
    csv_payload(destination_port="65536"),
    csv_payload(timestamp="no-time"),
    csv_payload(event_id="duplicate"),
])
def test_invalid_csv_returns_actionable_error(client, payload):
    r = client.post("/api/analyze-file", files={"file": ("test.csv", payload, "text/csv")})
    assert r.status_code == 400
    assert isinstance(r.json()["detail"], str)


def test_size_limit(client):
    r = client.post("/api/analyze-file", files={"file": ("big.csv", b"x"*(5*1024*1024+1), "text/csv")})
    assert r.status_code == 413


def test_wrong_extension(client):
    assert client.post("/api/analyze-file", files={"file": ("test.txt", b"x", "text/plain")}).status_code == 400


def test_invalid_id_and_provider(client):
    assert client.post("/api/ai-summary", json={"alert_ids":["not-a-real-alert"]}).status_code == 400
    assert client.post("/api/ai-summary", json={"provider":"not-a-provider"}).status_code == 422
    assert client.get("/api/analysis?analysis_id=missing").status_code == 404


def test_cloud_requires_consent(client):
    assert client.post("/api/ai-summary", json={"provider":"gemini"}).status_code == 400


def test_cross_origin_and_bad_host(client):
    assert client.post("/api/ai-summary", json={}, headers={"Origin":"https://attacker.example"}).status_code == 403
    assert client.get("/api/health", headers={"Host":"attacker.example"}).status_code == 400


def test_offline_report(client):
    response=client.post("/api/ai-summary",json={})
    assert response.status_code == 200
    assert response.json()["is_ai"] is False
    assert "not AI-generated" in response.json()["summary"]
    assert client.get("/api/report").status_code == 200
