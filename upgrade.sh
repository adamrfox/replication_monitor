#!/usr/bin/env bash
# ─── Qumulo Replication Monitor — Docker Upgrade Script ──────────────────────
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Qumulo Replication Monitor Upgrade ==="
echo ""

# Optional: pull latest code if running from a git repo
if [ -d .git ]; then
  echo "[1/3] Pulling latest code..."
  git pull
else
  echo "[1/3] Skipping git pull (not a git repo)"
fi

echo "[2/3] Building new image..."
docker compose build

echo "[3/3] Restarting container..."
docker compose up -d

echo ""
echo "Waiting for health check..."
sleep 5
docker compose ps

echo ""
echo "=== Upgrade complete ==="
echo "Logs: docker compose logs -f"
