#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Qumulo Replication Monitor — Install Script
# Run as root or with sudo.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

APP_DIR="/opt/qumulo-monitor"
DATA_DIR="/var/lib/qumulo-monitor"
NGINX_CONF="/etc/nginx/conf.d/qumulo-monitor.conf"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Qumulo Replication Monitor Installer ==="
echo ""

# ── 1. Check dependencies ────────────────────────────────────────────────────
echo "[1/7] Checking dependencies..."
command -v node >/dev/null 2>&1 || { echo "ERROR: Node.js not found. Install Node 18+ first."; exit 1; }
command -v npm  >/dev/null 2>&1 || { echo "ERROR: npm not found."; exit 1; }
command -v nginx >/dev/null 2>&1 || { echo "WARNING: nginx not found. Configure manually."; }

NODE_VER=$(node --version | cut -c2- | cut -d. -f1)
if [ "$NODE_VER" -lt 18 ]; then
  echo "ERROR: Node.js 18+ required (found $(node --version))"; exit 1
fi
echo "    Node.js $(node --version) ✓"

# ── 2. Create directories ────────────────────────────────────────────────────
echo "[2/7] Creating directories..."
mkdir -p "$APP_DIR" "$DATA_DIR"
chown nobody:nogroup "$DATA_DIR" 2>/dev/null || chown nobody "$DATA_DIR" 2>/dev/null || true

# ── 3. Copy application files ────────────────────────────────────────────────
echo "[3/7] Copying application files..."
cp -r "$SOURCE_DIR/backend"  "$APP_DIR/"
cp -r "$SOURCE_DIR/proxy"    "$APP_DIR/"
cp -r "$SOURCE_DIR/frontend" "$APP_DIR/"

# ── 4. Install Node dependencies ─────────────────────────────────────────────
echo "[4/7] Installing backend dependencies..."
cd "$APP_DIR/backend" && npm install --production

echo "      Installing proxy dependencies..."
cd "$APP_DIR/proxy" && npm install --production

echo "      Installing frontend dependencies and building..."
cd "$APP_DIR/frontend"
npm install
npm run build
echo "      Frontend built → $APP_DIR/frontend/dist"

# ── 5. Configure JWT secret ──────────────────────────────────────────────────
echo "[5/7] Generating JWT secret..."
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
SERVICE_FILE="$SOURCE_DIR/nginx/qumulo-monitor.service"
sed "s/CHANGE_THIS_TO_A_RANDOM_SECRET/$JWT_SECRET/" "$SERVICE_FILE" > /tmp/qumulo-monitor.service

# ── 6. Install systemd services ──────────────────────────────────────────────
echo "[6/7] Installing systemd services..."
cp "$SOURCE_DIR/nginx/qumulo-proxy.service"    /etc/systemd/system/
cp /tmp/qumulo-monitor.service                  /etc/systemd/system/qumulo-monitor.service

# Update paths in service files
sed -i "s|/opt/qumulo-monitor|$APP_DIR|g" /etc/systemd/system/qumulo-proxy.service
sed -i "s|/opt/qumulo-monitor|$APP_DIR|g" /etc/systemd/system/qumulo-monitor.service
sed -i "s|/var/lib/qumulo-monitor|$DATA_DIR|g" /etc/systemd/system/qumulo-monitor.service

systemctl daemon-reload
systemctl enable qumulo-proxy qumulo-monitor
systemctl start  qumulo-proxy
sleep 2
systemctl start  qumulo-monitor

echo "      Services started ✓"

# ── 7. Nginx configuration ───────────────────────────────────────────────────
echo "[7/7] Installing nginx configuration..."
if command -v nginx >/dev/null 2>&1; then
  cp "$SOURCE_DIR/nginx/qumulo-monitor.conf" "$NGINX_CONF"
  nginx -t && systemctl reload nginx && echo "      Nginx reloaded ✓" || echo "      WARNING: nginx config test failed. Check $NGINX_CONF"
else
  echo "      Nginx not found — copy nginx/qumulo-monitor.conf manually."
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Qumulo Replication Monitor installed!"
echo ""
echo "  URL:      http://$(hostname -I | awk '{print $1}'):3008"
echo "  Login:    admin / admin  (change immediately!)"
echo ""
echo "  Services: systemctl status qumulo-monitor"
echo "            systemctl status qumulo-proxy"
echo "  Logs:     journalctl -u qumulo-monitor -f"
echo "            journalctl -u qumulo-proxy -f"
echo ""
echo "  Data:     $DATA_DIR/qumulo-monitor.db"
echo "═══════════════════════════════════════════════════════════"
