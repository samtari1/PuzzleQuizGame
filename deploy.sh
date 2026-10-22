#!/bin/sh
set -eu

APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEPLOY_CONFIG=/etc/ict-escape/deploy.conf
DEFAULT_REPO_URL=https://github.com/samtari1/PuzzleQuizGame.git
REPO_BRANCH=main
DRY_RUN=0

usage() {
  cat <<'EOF'
Update the VPS checkout from the GitHub main branch and restart the app.

Run this on the VPS:
  sudo /var/www/PuzzleQuizGame/deploy.sh [--dry-run]

Options:
  --dry-run  Fetch main and list commits that would be deployed.
  --help     Show this help.

The app checkout is reset to origin/main. Keep secrets and SQLite data outside it.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script with sudo: sudo $APP_DIR/deploy.sh" >&2
  exit 1
fi

if [ -f "$DEPLOY_CONFIG" ]; then
  # Optional override for private repositories or a different GitHub URL.
  set -a
  . "$DEPLOY_CONFIG"
  set +a
fi
REPO_URL=${REPO_URL:-$DEFAULT_REPO_URL}

if ! command -v git >/dev/null 2>&1; then
  echo "git is required. Install it with: sudo apt install git" >&2
  exit 1
fi
if ! git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "$APP_DIR is not a Git checkout. Clone the repository there first; see README.md." >&2
  exit 1
fi
if [ ! -f /etc/ict-escape/ict-escape.env ]; then
  echo "Missing /etc/ict-escape/ict-escape.env. Configure the app environment first." >&2
  exit 1
fi

REMOTE_URL=$(git -C "$APP_DIR" remote get-url origin)
if [ "$REMOTE_URL" != "$REPO_URL" ]; then
  git -C "$APP_DIR" remote set-url origin "$REPO_URL"
fi

echo "Fetching origin/$REPO_BRANCH..."
git -C "$APP_DIR" fetch --prune origin "+refs/heads/$REPO_BRANCH:refs/remotes/origin/$REPO_BRANCH"

if [ "$DRY_RUN" -eq 1 ]; then
  AHEAD_COUNT=$(git -C "$APP_DIR" rev-list --count "HEAD..origin/$REPO_BRANCH")
  if [ "$AHEAD_COUNT" -eq 0 ]; then
    echo "Already up to date with origin/$REPO_BRANCH."
  else
    echo "Commits that would be deployed:"
    git -C "$APP_DIR" log --oneline "HEAD..origin/$REPO_BRANCH"
  fi
  exit 0
fi

echo "Updating checkout to origin/$REPO_BRANCH..."
git -C "$APP_DIR" reset --hard "origin/$REPO_BRANCH"

if ! test -x "$APP_DIR/.venv/bin/python"; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt"
install -m 0644 "$APP_DIR/deploy/ict-escape.service.example" /etc/systemd/system/ict-escape.service
systemctl daemon-reload
systemctl enable ict-escape
systemctl restart ict-escape
systemctl --no-pager --full status ict-escape

echo "Deployment complete."
