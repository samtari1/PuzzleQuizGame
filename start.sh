#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

if [ ! -x .venv/bin/python ]; then
  echo "Virtual environment not found. Run ./setup.sh first." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo ".env not found. Run ./setup.sh, then edit .env before starting." >&2
  exit 1
fi

# Export values from .env for this process. Keep the file in shell-compatible KEY=value format.
set -a
. ./.env
set +a

if [ -z "${FLASK_SECRET_KEY:-}" ] || [ "$FLASK_SECRET_KEY" = "replace-with-a-long-random-secret" ]; then
  echo "Set FLASK_SECRET_KEY in .env before starting." >&2
  exit 1
fi
if [ -z "${INSTRUCTOR_PASSWORD:-}" ] || [ "$INSTRUCTOR_PASSWORD" = "replace-with-a-strong-instructor-password" ]; then
  echo "Set INSTRUCTOR_PASSWORD in .env before starting." >&2
  exit 1
fi

exec .venv/bin/python app.py
