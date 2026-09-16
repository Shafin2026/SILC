"""Validate untrusted CSV input without evaluating it."""
from __future__ import annotations
from io import BytesIO
from ipaddress import ip_address
import pandas as pd

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 20_000
REQUIRED = {"event_id", "timestamp", "source_ip", "destination_ip", "destination_port",
            "protocol", "tcp_flags", "username", "auth_result", "dns_query",
            "http_status", "redirect_domain"}


def read_events(source) -> pd.DataFrame:
    try:
        frame = pd.read_csv(source, dtype=str, keep_default_na=False, nrows=MAX_ROWS + 1)
    except (ValueError, UnicodeError, pd.errors.ParserError) as exc:
        raise ValueError("Use a UTF-8 CSV with a header row matching the sample schema.") from exc
    return validate_events(frame)


def read_bytes(content: bytes) -> pd.DataFrame:
    if len(content) > MAX_BYTES:
        raise ValueError("CSV must be 5 MB or smaller.")
    return read_events(BytesIO(content))


def validate_events(frame: pd.DataFrame) -> pd.DataFrame:
    missing = REQUIRED - set(frame.columns)
    if missing:
        raise ValueError("Missing columns: " + ", ".join(sorted(missing)))
    if frame.empty or len(frame) > MAX_ROWS:
        raise ValueError("CSV must have between 1 and 20,000 rows.")
    if len(frame.columns) > 32:
        raise ValueError("CSV may contain at most 32 columns.")
    frame = frame.fillna("").copy()
    for col in frame.columns:
        frame[col] = frame[col].astype(str).str.strip()
        if frame[col].str.len().gt(512).any():
            raise ValueError(f"Values in {col} must be 512 characters or shorter.")
    if frame["event_id"].eq("").any() or frame["event_id"].duplicated().any():
        raise ValueError("Each event_id must be nonempty and unique.")
    for col in ["source_ip", "destination_ip"]:
        try:
            for value in frame[col].unique():
                ip_address(value)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address in {col}.") from exc
    try:
        if not frame["timestamp"].str.contains(r"(?:Z|[+-]\d{2}:\d{2})$", regex=True).all():
            raise ValueError("timezone")
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="ISO8601")
        if (frame["timestamp"].max() - frame["timestamp"].min()).total_seconds() > 7 * 86400:
            raise ValueError("timestamp range")
        ports = pd.to_numeric(frame["destination_port"], errors="raise")
        if not (ports.between(0, 65535) & ports.mod(1).eq(0)).all():
            raise ValueError("port")
        frame["destination_port"] = ports.astype(int)
        status = pd.to_numeric(frame["http_status"].replace("", "0"), errors="raise")
        if not (status.eq(0) | (status.between(100, 599) & status.mod(1).eq(0))).all():
            raise ValueError("HTTP status")
        frame["http_status"] = status.astype(int)
    except (ValueError, TypeError) as exc:
        raise ValueError("Use timezone-qualified ISO timestamps within a 7-day range, ports 0-65535, and valid HTTP status codes (or blank).") from exc
    frame["protocol"] = frame["protocol"].str.upper()
    frame["tcp_flags"] = frame["tcp_flags"].str.upper()
    frame["auth_result"] = frame["auth_result"].str.lower()
    if not frame["protocol"].isin(["TCP", "UDP", "DNS", "HTTP", "ICMP"]).all():
        raise ValueError("Protocol must be TCP, UDP, DNS, HTTP, or ICMP.")
    if not frame["auth_result"].isin(["", "success", "failure"]).all():
        raise ValueError("auth_result must be blank, success, or failure.")
    for col in ["dns_query", "redirect_domain"]:
        frame[col] = frame[col].str.lower().str.rstrip(".")
    return frame.sort_values(["timestamp", "event_id"]).reset_index(drop=True)
