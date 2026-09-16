#!/usr/bin/env bash
# Run from any folder: type bash and a space, then drag this file into Terminal.
set -euo pipefail
cd -- "$(dirname -- "$0")"
SILC_PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(not ((3,11) <= sys.version_info[:2] <= (3,13)))' 2>/dev/null; then
    SILC_PYTHON="$candidate"
    break
  fi
done
if [ -z "$SILC_PYTHON" ]; then
  echo "Install Python 3.11, 3.12, or 3.13 from python.org, then run this script again."
  exit 1
fi
if [ ! -d ".venv" ]; then
  "$SILC_PYTHON" -m venv .venv
fi
if ! .venv/bin/python -c 'import sys; sys.exit(not ((3,11) <= sys.version_info[:2] <= (3,13)))' 2>/dev/null; then
  echo "This project environment is incomplete or uses an unsupported Python. Extract a fresh copy, then run its start.sh."
  exit 1
fi
echo "Checking project dependencies (internet needed on the first run)..."
.venv/bin/python -m pip install -r requirements.txt
if [ ! -f "data/network_events.csv" ]; then
  .venv/bin/python scripts/generate_events.py
fi
exec .venv/bin/python scripts/launch.py "$@"
