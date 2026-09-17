"""Same-origin, single-user local lab. Not a public production service."""
from __future__ import annotations
import asyncio
import json
import secrets
import time
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from src.ai_providers import AIProviderError, CLOUD, configured_providers, summarize_alerts
from src.analyze import build_report, load_events
from src.detections import run_all_detections
from src.validation import MAX_BYTES, read_bytes
from src.rules import RULES
from src.intelligence import fingerprint, public_alert, event_links, context, ai_context, context_report, records

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
DEFAULT_EVENTS = ROOT / "data" / "network_events.csv"
UPLOADS: OrderedDict = OrderedDict()
AI_LOCK = asyncio.Lock()
app = FastAPI(title="SILC · Security Intelligence & Log Correlation", version="3.0.0",
              description="Local defensive lab. Synthetic demo; no live monitoring. AI drafts need human review.")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[
        "127.0.0.1",
        "localhost",
        "testserver",
        "*.vercel.app",
    ],
)


class BodyLimit:
    """Bound bodies BEFORE Starlette parses multipart data, even without Content-Length."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            return await self.app(scope, receive, send)
        content = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            content.extend(message.get("body", b""))
            if len(content) > MAX_BYTES + 65536:
                return await JSONResponse({"detail": "Request too large. CSV limit is 5 MB."}, 413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False
        async def bounded_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(content), "more_body": False}
        await self.app(scope, bounded_receive, send)


app.add_middleware(BodyLimit)


@app.middleware("http")
async def browser_boundary(request: Request, call_next):
    if request.method == "POST" and request.headers.get("origin"):
        origin = urlparse(request.headers["origin"])
        if origin.scheme not in {"http", "https"} or origin.netloc != request.headers.get("host"):
            return JSONResponse({"detail": "Cross-origin requests are not allowed."}, 403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    # Swagger uses external assets. The API schema still works offline.
    if request.url.path == "/docs":
        del response.headers["Content-Security-Policy"]
    return response


class BriefRequest(BaseModel):
    analysis_id: str = Field(default="sample", max_length=64)
    alert_ids: list[str] = Field(default_factory=list, max_length=10)
    provider: Literal["offline", "ollama", "gemini", "deepseek", "openai", "anthropic"] = "offline"
    consent_to_cloud: bool = False


def make_analysis(events, analysis_id, name, synthetic):
    alerts = run_all_detections(events)
    return {"events": events, "alerts": alerts, "id": analysis_id, "name": name,
            "synthetic": synthetic, "created": time.monotonic(), "fingerprint": fingerprint(events),
            "event_links": event_links(alerts)}


@lru_cache(maxsize=1)
def sample():
    if not DEFAULT_EVENTS.exists():
        raise HTTPException(503, "Sample missing. Run python scripts/generate_events.py.")
    return make_analysis(load_events(DEFAULT_EVENTS), "sample", "September network lab", True)


def get_analysis(analysis_id):
    if analysis_id == "sample":
        return sample()
    item = UPLOADS.get(analysis_id)
    if not item or time.monotonic() - item["created"] > 3600:
        UPLOADS.pop(analysis_id, None)
        raise HTTPException(404, "Upload expired. Upload the CSV again (kept for 1 hour, up to 3 uploads).")
    return item


def public_analysis(item):
    events, alerts = item["events"], item["alerts"]
    timeline = events.set_index("timestamp").resample("10min").size()
    matched = events["event_id"].isin({e for ids in alerts["evidence_ids"] for e in ids})
    starts = pd.to_datetime(alerts["first_seen"], utc=True).dt.floor("10min").value_counts() if len(alerts) else {}
    return {
        "analysis_id": item["id"], "name": item["name"], "synthetic": item["synthetic"],
        "fingerprint": item["fingerprint"],
        "events_analyzed": len(events), "alerts_generated": len(alerts),
        "severity_counts": {k: int((alerts["severity"] == k).sum()) for k in ["Critical", "High", "Medium", "Low"]},
        "alert_type_counts": alerts["alert_type"].value_counts().to_dict(),
        "protocol_counts": events["protocol"].value_counts().to_dict(),
        "first_seen": events["timestamp"].min().isoformat(), "last_seen": events["timestamp"].max().isoformat(),
        "unique_sources": events["source_ip"].nunique(),
        "evidence_events_previewed": int(matched.sum()),
        "linked_events": len(item["event_links"]),
        "timeline": [{"time": t.isoformat(), "events": int(n), "alerts": int(starts.get(t, 0))} for t, n in timeline.items()],
        "top_sources": [{"ip": ip, "events": int(n)} for ip, n in events["source_ip"].value_counts().head(5).items()],
        "alerts": [public_alert(a, item["fingerprint"]) for a in alerts.head(500).to_dict(orient="records")], "alerts_truncated": len(alerts) > 500,
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "mode": "local-lab", "version": "3.0.0"}


@app.get("/api/analysis")
def analysis(analysis_id: str = "sample"):
    return public_analysis(get_analysis(analysis_id))


@app.get("/api/summary")
def summary(analysis_id: str = "sample"):
    result = public_analysis(get_analysis(analysis_id))
    result.pop("alerts")
    return result


@app.get("/api/alerts")
def alerts(analysis_id: str = "sample", severity: str | None = None, limit: int = Query(100, ge=1, le=500)):
    item = get_analysis(analysis_id)
    frame = item["alerts"]
    if severity:
        frame = frame[frame["severity"].str.lower() == severity.lower()]
    return [public_alert(a, item["fingerprint"]) for a in frame.head(limit).to_dict(orient="records")]


@app.get("/api/context/{alert_id}")
def investigation(alert_id: str, analysis_id: str = "sample"):
    item = get_analysis(analysis_id)
    found = item["alerts"][item["alerts"]["alert_id"] == alert_id]
    if found.empty:
        raise HTTPException(404, "Alert not found in this analysis.")
    return context(item, found.iloc[0].to_dict())


@app.get("/api/events")
def search_events(analysis_id: str = "sample", q: str = Query("", max_length=128),
                  protocol: str = Query("", max_length=16), linked_only: bool = False,
                  severity: Literal["Critical", "High", "Medium", "Low"] | None = None,
                  start: str | None = Query(None, max_length=48), end: str | None = Query(None, max_length=48),
                  offset: int = Query(0, ge=0, le=20000), limit: int = Query(50, ge=1, le=100)):
    item = get_analysis(analysis_id)
    frame = item["events"]
    if q:
        cols = ["event_id", "source_ip", "destination_ip", "username", "dns_query", "redirect_domain"]
        mask = pd.Series(False, index=frame.index)
        for column in cols:
            mask |= frame[column].astype(str).str.contains(q, case=False, regex=False)
        frame = frame[mask]
    if protocol:
        frame = frame[frame["protocol"] == protocol.upper()]
    if linked_only:
        frame = frame[frame["event_id"].isin(item["event_links"])]
    if severity:
        wanted = set(item["alerts"].loc[item["alerts"]["severity"] == severity, "alert_id"])
        ids = {event_id for event_id, links in item["event_links"].items() if wanted.intersection(links)}
        frame = frame[frame["event_id"].isin(ids)]
    try:
        for value, is_start in [(start, True), (end, False)]:
            if value:
                stamp = pd.Timestamp(value)
                if stamp.tzinfo is None or pd.isna(stamp):
                    raise ValueError()
                frame = frame[frame["timestamp"] >= stamp] if is_start else frame[frame["timestamp"] < stamp]
    except (ValueError, TypeError, OverflowError):
        raise HTTPException(400, "Time filters require a valid timestamp with a timezone.") from None
    frame = frame.sort_values(["timestamp", "event_id"])
    output = records(frame.iloc[offset:offset + limit])
    for row in output:
        row["alert_ids"] = item["event_links"].get(row["event_id"], [])
    return {"total": len(frame), "offset": offset, "limit": limit, "events": output}


@app.get("/api/evidence/{alert_id}")
def evidence(alert_id: str, analysis_id: str = "sample"):
    item = get_analysis(analysis_id)
    matched = item["alerts"][item["alerts"]["alert_id"] == alert_id]
    if matched.empty:
        raise HTTPException(404, "Alert not found in this analysis.")
    alert = matched.iloc[0]
    frame = item["events"][item["events"]["event_id"].isin(alert["evidence_ids"])].copy()
    frame["timestamp"] = frame["timestamp"].map(lambda t: t.isoformat())
    return {"total": int(alert["event_count"]), "shown": len(frame), "events": frame.to_dict(orient="records")}


@app.get("/api/rules")
def rules():
    return RULES


@app.get("/api/providers")
def providers():
    return configured_providers()


@app.get("/api/sample.csv")
def sample_csv():
    return FileResponse(DEFAULT_EVENTS, filename="network_events.csv", media_type="text/csv")


@app.get("/api/report")
def report(analysis_id: str = "sample"):
    item = get_analysis(analysis_id)
    return PlainTextResponse(build_report(item["events"], item["alerts"], item["synthetic"]) + context_report(item), media_type="text/markdown",
                             headers={"Content-Disposition": 'attachment; filename="incident_report.md"'})


@app.post("/api/analyze-file")
async def analyze_file(file: UploadFile):
    try:
        if not file.filename or not file.filename.lower().endswith(".csv"):
            raise HTTPException(400, "Choose a .csv file.")
        content = await file.read(MAX_BYTES + 1)
        if len(content) > MAX_BYTES:
            raise HTTPException(413, "CSV must be 5 MB or smaller.")
        events = await run_in_threadpool(read_bytes, content)
        analysis_id = secrets.token_hex(12)
        name = Path(file.filename.replace("\\", "/")).name[:100]
        item = await run_in_threadpool(make_analysis, events, analysis_id, name, False)
        for key in list(UPLOADS):
            if time.monotonic() - UPLOADS[key]["created"] > 3600:
                UPLOADS.pop(key)
        while len(UPLOADS) >= 3:
            UPLOADS.popitem(last=False)
        UPLOADS[analysis_id] = item
        return public_analysis(item)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    finally:
        await file.close()


@app.post("/api/ai-summary")
async def brief(request: BriefRequest):
    item = get_analysis(request.analysis_id)
    frame = item["alerts"]
    selected = frame.head(5)
    if request.alert_ids:
        ids = list(dict.fromkeys(request.alert_ids))
        if not set(ids).issubset(set(frame["alert_id"])):
            raise HTTPException(400, "One or more alert IDs do not belong to this analysis.")
        selected = frame[frame["alert_id"].isin(ids)]
    if selected.empty:
        raise HTTPException(400, "No alerts to summarize.")
    if request.provider in CLOUD and not request.consent_to_cloud:
        raise HTTPException(400, "Confirm that selected alert evidence may be sent to the cloud provider.")
    if AI_LOCK.locked():
        raise HTTPException(429, "A briefing is already running. Wait before trying again.")
    try:
        async with AI_LOCK:
            enriched = await run_in_threadpool(lambda: [ai_context(item, a) for a in selected.to_dict(orient="records")])
            result = await summarize_alerts(enriched, request.provider)
    except AIProviderError as exc:
        raise HTTPException(502, str(exc)) from None
    return {**result, "analysis_id": item["id"], "alert_ids": selected["alert_id"].tolist(),
            "disclaimer": "Draft only. Validate evidence and recommendations before any response."}


app.mount("/assets", StaticFiles(directory=ROOT / "frontend"), name="assets")


@app.get("/", include_in_schema=False)
def frontend():
    return FileResponse(ROOT / "frontend" / "index.html")
