import pandas as pd

from src.detections import run_all_detections


def base_event(**updates):
    event = {
        "timestamp": "2026-09-01T08:00:00+00:00",
        "source_ip": "203.0.113.10",
        "destination_ip": "172.16.0.10",
        "destination_port": 22,
        "protocol": "TCP",
        "tcp_flags": "ACK",
        "username": "admin",
        "auth_result": "",
        "dns_query": "",
        "redirect_domain": "",
        "http_status": 0,
    }
    event.update(updates)
    return event


def frame(events):
    result = pd.DataFrame(events)
    result["event_id"] = [f"TEST-{i:04}" for i in range(len(result))]
    result["timestamp"] = pd.to_datetime(result["timestamp"], utc=True)
    return result


def test_brute_force_detection():
    alerts = run_all_detections(frame([
        base_event(auth_result="failure") for _ in range(8)
    ]))
    assert "Possible brute force" in alerts["alert_type"].tolist()


def test_suspicious_dns_detection():
    alerts = run_all_detections(frame([
        base_event(protocol="DNS", destination_port=53, dns_query="credential-check.example")
    ]))
    assert alerts.iloc[0]["alert_type"] == "Suspicious DNS query"
    assert alerts.iloc[0]["severity"] == "High"


def test_normal_event_does_not_alert():
    alerts = run_all_detections(frame([base_event()]))
    assert alerts.empty


def test_port_scan_threshold():
    alerts = run_all_detections(frame([base_event(destination_port=p) for p in range(12)]))
    assert alerts.iloc[0]["alert_type"] == "Port scan"
    assert alerts.iloc[0]["event_count"] == 12
    assert len(alerts.iloc[0]["evidence_ids"]) == 12


def test_syn_flood_and_below_threshold():
    events = [base_event(tcp_flags="SYN") for _ in range(60)]
    assert run_all_detections(frame(events)).iloc[0]["severity"] == "Critical"
    assert run_all_detections(frame(events[:59])).empty


def test_redirect_requires_http_and_3xx():
    event = base_event(protocol="HTTP", http_status=302, redirect_domain="greatrecipesforme.example")
    assert run_all_detections(frame([event])).iloc[0]["alert_type"] == "Suspicious HTTP redirect"
    assert run_all_detections(frame([{**event, "http_status": 200}])).empty
    assert run_all_detections(frame([{**event, "protocol": "TCP"}])).empty


def test_dns_requires_dns_protocol():
    assert run_all_detections(frame([base_event(dns_query="credential-check.example")])).empty


def test_fixed_window_limitation_is_explicit():
    events = [base_event(auth_result="failure", timestamp="2026-09-01T08:04:59Z") for _ in range(4)]
    events += [base_event(auth_result="failure", timestamp="2026-09-01T08:05:01Z") for _ in range(4)]
    assert run_all_detections(frame(events)).empty


def test_alert_ids_are_stable():
    events = frame([base_event(auth_result="failure") for _ in range(8)])
    assert run_all_detections(events).iloc[0]["alert_id"] == run_all_detections(events.iloc[::-1]).iloc[0]["alert_id"]
