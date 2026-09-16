"""Launch SILC on an available loopback port and open it after startup."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn


def reserve_port():
    # Hold the selected socket for Uvicorn so another process cannot claim it.
    for port in range(8000, 8006):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
            listener.listen(128)
            return listener, port
        except OSError:
            listener.close()
    raise RuntimeError("Ports 8000–8005 are busy. Stop an earlier SILC Terminal with Control+C, then try again.")


def open_when_ready(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with opener.open(url + "/api/health", timeout=1) as response:
                healthy = json.load(response).get("status") == "ok"
            if healthy:
                webbrowser.open(url)
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.3)


def main():
    parser = argparse.ArgumentParser(description="Start the local SILC workspace.")
    parser.add_argument("--no-browser", action="store_true", help="Print the address without opening a browser")
    args = parser.parse_args()
    try:
        listener, port = reserve_port()
    except RuntimeError as error:
        print(str(error), flush=True)
        return 1
    url = f"http://127.0.0.1:{port}"
    print(f"\nSILC · Security Intelligence & Log Correlation\nOpen {url}\nKeep this Terminal open. Control+C stops SILC.\nAI is optional; no API key is needed to start.\n", flush=True)
    if not args.no_browser:
        threading.Thread(target=open_when_ready, args=(url,), daemon=True).start()
    config = uvicorn.Config("src.api:app", host="127.0.0.1", port=port, log_level="info")
    try:
        uvicorn.Server(config).run(sockets=[listener])
    except KeyboardInterrupt:
        print("\nSILC stopped.", flush=True)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
