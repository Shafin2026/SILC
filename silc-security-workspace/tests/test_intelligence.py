import asyncio
import copy
import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api import app, sample, public_analysis, make_analysis
from src.intelligence import context, ai_context
from src.ai_providers import parse_explanations, offline_explanations, summarize_alerts, AIProviderError


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def selected():
    item = sample()
    return [ai_context(item, a) for a in item["alerts"].head(2).to_dict(orient="records")]


def valid_output(alerts):
    return {"summary": "Selected evidence requires analyst review.", "explanations": offline_explanations(alerts)}


def test_all_cases_have_explainable_evidence():
    item = sample()
    for a in item["alerts"].to_dict(orient="records"):
        c = context(item, a)
        assert c["reasoning"]["rule_trigger"]
        assert c["reasoning"]["false_positives"]
        assert c["reasoning"]["missing_telemetry"]
        assert c["reasoning"]["confidence_note"]
        assert {e["event_id"] for e in c["evidence"]} == set(a["evidence_ids"])
        assert all(a["alert_id"] in e["alert_ids"] for e in c["evidence"])
        assert c["attack_path"][0]["kind"] == "observed"
        assert c["attack_path"][1]["kind"] == "hypothesis"
        assert c["attack_path"][1]["confidence"] == "Not assessed"


def test_observed_threshold_and_dataset_baseline_are_separate():
    item = sample()
    c = context(item, item["alerts"].iloc[0].to_dict())
    b = c["reasoning"]["comparison"]
    assert b["observed"] == 85
    assert b["threshold"] == 60
    assert b["median"] == 0
    assert b["earlier_buckets"] == 120
    assert "does not trigger the alert" in b["note"]


def test_no_prior_history_is_not_presented_as_zero_baseline():
    item = sample()
    a = item["alerts"].iloc[0].to_dict()
    cropped = item["events"][item["events"]["event_id"].isin(a["_evidence_ids"])]
    small = make_analysis(cropped.copy(), "crop", "Cropped", True)
    c = context(small, small["alerts"].iloc[0].to_dict())
    assert c["reasoning"]["comparison"]["median"] is None
    assert not c["reasoning"]["comparison"]["available"]


def test_case_identity_matches_identical_data_not_file_name():
    item = sample()
    second = make_analysis(item["events"].copy(), "other-upload", "Renamed.csv", False)
    assert public_analysis(item)["alerts"][0]["case_id"] == public_analysis(second)["alerts"][0]["case_id"]
    changed = item["events"].copy()
    changed.loc[0, "username"] = "a-different-context"
    third = make_analysis(changed, "another", "Same name", False)
    assert third["fingerprint"] != item["fingerprint"]


def test_full_event_search_and_pagination(client):
    result = client.get("/api/events", params={"linked_only": True, "limit": 100}).json()
    assert result["total"] == 124
    assert len(result["events"]) == 100
    assert all(e["alert_ids"] for e in result["events"])
    tail = client.get("/api/events", params={"linked_only": True, "offset": 100}).json()
    assert len(tail["events"]) == 24
    assert not set(e["event_id"] for e in result["events"]) & set(e["event_id"] for e in tail["events"])
    assert client.get("/api/events", params={"q": "no-such-host"}).json()["total"] == 0
    critical = client.get("/api/events", params={"severity": "Critical"}).json()
    assert critical["total"] == 85


def test_events_time_filter_and_validation(client):
    result = client.get("/api/events", params={"start": "2026-09-01T10:00:00Z", "end": "2026-09-01T10:01:00Z", "linked_only": True}).json()
    assert result["total"] == 85
    assert client.get("/api/events", params={"start": "2026-09-01"}).status_code == 400
    assert client.get("/api/events", params={"limit": 101}).status_code == 422
    assert client.get("/api/events", params={"q": "a"*129}).status_code == 422


def test_internal_ids_not_exposed_in_public_alerts(client):
    data = client.get("/api/analysis").json()
    assert data["linked_events"] == 124
    assert sum(b["alerts"] for b in data["timeline"]) == 10
    assert all("_evidence_ids" not in a for a in data["alerts"])
    assert "_evidence_ids" not in client.get("/api/alerts").text


def test_preview_and_full_index_when_more_than_100_rows():
    item = sample()
    a = item["alerts"].iloc[0].to_dict()
    frame = item["events"][item["events"]["event_id"].isin(a["_evidence_ids"])].copy()
    extra = frame.iloc[:45].copy()
    extra["event_id"] = [f"ZZZ-{i}" for i in range(45)]
    frame = pd.concat([frame, extra], ignore_index=True)
    data = make_analysis(frame, "large", "Large burst", True)
    alert = data["alerts"].iloc[0].to_dict()
    c = context(data, alert)
    assert c["reasoning"]["comparison"]["observed"] == 130
    assert c["reasoning"]["evidence_available"] == 130
    assert len(c["evidence"]) == 100
    assert len(data["event_links"]) == 130
    assert set(e["event_id"] for e in c["evidence"]) == set(alert["evidence_ids"])


def test_context_unknown_or_expired(client):
    assert client.get("/api/context/unknown").status_code == 404
    assert client.get("/api/context/unknown?analysis_id=expired").status_code == 404


def test_offline_explanation_has_reasoning_without_prediction():
    result = asyncio.run(summarize_alerts(selected(), "offline"))
    assert not result["is_ai"]
    assert len(result["explanations"]) == 2
    assert all(e["rationale"] and e["prediction_confidence"] == "Not assessed" for e in result["explanations"])
    assert "not AI-generated" in result["summary"]


@pytest.mark.parametrize("change", ["missing_reasoning","unknown_evidence","foreign_alert","duplicate","partial","numeric_confidence","action_key"])
def test_model_must_return_bound_complete_explanations(change):
    alerts = selected()
    output = valid_output(alerts)
    e = output["explanations"][0]
    if change == "missing_reasoning": del e["rationale"]
    elif change == "unknown_evidence": e["evidence_ids"] = ["invented-log"]
    elif change == "foreign_alert": e["alert_id"] = "ALT-NOTSELECTED"
    elif change == "duplicate": output["explanations"][1] = copy.deepcopy(e)
    elif change == "partial": output["explanations"].pop()
    elif change == "numeric_confidence": e["prediction_confidence"] = 0.98
    elif change == "action_key": e["execute_command"] = "do something"
    with pytest.raises(AIProviderError, match="evidence-linked"):
        parse_explanations(json.dumps(output), alerts)


def test_supported_json_and_empty_or_oversized_output():
    alerts = selected()
    output = valid_output(alerts)
    fence = chr(96) * 3
    assert len(parse_explanations(fence+"json\n"+json.dumps(output)+"\n"+fence, alerts)["explanations"]) == 2
    for value in ["", "plain prose without citations", "x"*64001]:
        with pytest.raises(AIProviderError):
            parse_explanations(value, alerts)


def test_report_contains_case_and_reasoning(client):
    report = client.get("/api/report").text
    assert "INC-" in report and "Why flagged:" in report
    assert "Hypothesis, not observed:" in report
    assert "Missing telemetry:" in report


def test_correlation_counts_are_actual_records():
    item = sample()
    c = context(item, item["alerts"].iloc[0].to_dict())
    assert c["graph"]["edges"]
    assert "not proof of causation" in c["correlation_note"]
    assert all(e["events"] >= 1 for e in c["graph"]["edges"])
    ids={e["event_id"] for e in c["evidence"]}
    assert not ids & {e["event_id"] for e in c["related_events"]}
