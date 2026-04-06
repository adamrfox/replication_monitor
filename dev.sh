#!/usr/bin/env bash
# Quick dev startup — runs all three processes in parallel
# Usage: ./dev.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$ROOT/data"
mkdir -p "$DATA_DIR"

# Install deps if needed
[ -d "$ROOT/proxy/node_modules" ]    || (cd "$ROOT/proxy"    && npm install)
[ -d "$ROOT/backend/node_modules" ]  || (cd "$ROOT/backend"  && npm install)
[ -d "$ROOT/frontend/node_modules" ] || (cd "$ROOT/frontend" && npm install)

echo "Starting Qumulo Monitor (dev mode)..."
echo "  Proxy:    http://127.0.0.1:3007"
echo "  Backend:  http://localhost:3006"
echo "  Frontend: http://localhost:3005  ← open this"
echo ""
echo "Press Ctrl+C to stop all processes."
echo ""

# Start proxy
PROXY_PORT=3007 node "$ROOT/proxy/proxy.js" &
PROXY_PID=$!

# Start backend
BACKEND_PORT=3006 \
PROXY_URL=http://127.0.0.1:3007 \
DB_PATH="$DATA_DIR/qumulo-monitor.db" \
JWT_SECRET=dev-secret-not-for-production \
FRONTEND_ORIGIN=http://localhost:3005 \
node "$ROOT/backend/src/index.js" &
BACKEND_PID=$!

# Start frontend dev server
cd "$ROOT/frontend" && npm run dev &
FRONTEND_PID=$!

# Cleanup on exit
cleanup() {
  echo ""
  echo "Stopping services..."
  kill $PROXY_PID $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait
