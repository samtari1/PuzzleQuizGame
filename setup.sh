#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required. Install Python 3.9 or newer." >&2
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
  echo "Error: Python 3.9 or newer is required (found $PYTHON_VERSION)." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit it and set FLASK_SECRET_KEY and INSTRUCTOR_PASSWORD before starting."
fi

# Create the SQLite schema without starting the web server.
.venv/bin/python -c 'import app'

echo "Setup complete. Edit .env, then run ./start.sh"
