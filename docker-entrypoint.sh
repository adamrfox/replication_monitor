#!/bin/sh
# ─── Qumulo Replication Monitor — Docker Entrypoint ──────────────────────────
# Starts the internal HTTPS proxy and the backend API as concurrent processes.
# Uses a simple process group so both die if either exits.

set -e

# Generate a JWT secret if not provided
if [ -z "$JWT_SECRET" ]; then
  export JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  echo "[entrypoint] JWT_SECRET not set — generated a random one for this session."
  echo "[entrypoint] Set JWT_SECRET in your environment or docker-compose.yml to persist sessions across restarts."
fi

echo "[entrypoint] Starting Qumulo HTTPS Proxy on port ${PROXY_PORT:-3007}..."
node /app/proxy/proxy.js &
PROXY_PID=$!

# Brief pause to let proxy bind its port before backend tries to use it
sleep 1

echo "[entrypoint] Starting Qumulo Monitor Backend on port ${BACKEND_PORT:-3006}..."
node /app/backend/src/index.js &
BACKEND_PID=$!

# If either process dies, kill the other and exit
wait_and_exit() {
  echo "[entrypoint] A process exited — shutting down..."
  kill $PROXY_PID $BACKEND_PID 2>/dev/null
  exit 1
}

trap wait_and_exit TERM INT

# Wait for either process to exit
wait $PROXY_PID $BACKEND_PID
