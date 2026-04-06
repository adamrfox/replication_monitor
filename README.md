# Qumulo Replication Monitor

A self-hosted web application that monitors Qumulo replication jobs, reports their status, and sends email alerts when jobs enter an error state or fall behind a configurable lag threshold.

---

## Architecture

```
Browser
  │
  ▼
Nginx (port 3008)          ← Single public-facing port
  ├── /api/*  ──────────►  Backend API  (port 3006, Express + SQLite)
  │                              │
  │                              │  HTTP (localhost only)
  │                              ▼
  │                         HTTPS Proxy  (port 3007, internal)
  │                              │  Bypasses SSL cert validation
  │                              ▼
  │                         Qumulo Clusters (any port, HTTP or HTTPS)
  │
  └── /*  ────────────────► React SPA (served by backend in production)
```

### Port Assignment

| Service       | Port | Notes                                      |
|---------------|------|--------------------------------------------|
| Nginx (app)   | 3008 | Only public-facing port                    |
| Backend API   | 3006 | Express; also serves built frontend        |
| HTTPS Proxy   | 3007 | Internal only; bound to 127.0.0.1          |
| Frontend dev  | 3005 | Development only (Vite)                    |

Ports 3000, 3001, 3002, and 8081 are left untouched.

---

## Quick Start (Development)

```bash
# 1. Clone / extract project
cd qumulo-monitor

# 2. Run everything
chmod +x dev.sh
./dev.sh

# 3. Open browser
open http://localhost:3005

# Default credentials: admin / admin
# Change password immediately after first login!
```

---

## Production Install

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer will:
1. Install npm dependencies for all three services
2. Build the React frontend
3. Generate a random JWT secret
4. Install and start systemd services (`qumulo-proxy`, `qumulo-monitor`)
5. Install the nginx configuration

After install, access the app at `http://<your-server>:3008`.

### Manual Nginx Setup

Copy `nginx/qumulo-monitor.conf` to `/etc/nginx/conf.d/` and reload nginx:

```bash
sudo cp nginx/qumulo-monitor.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx
```

---

## Features

### Dashboard
- Live status cards for all monitored replication relationships
- Color-coded status: OK (green), Lagging (yellow), Error (red), Running (blue)
- Click any stat to filter by status
- Auto-refreshes every 30 seconds

### Relationships
- Table view of all relationships with live status and lag
- Per-relationship lag threshold override
- Enable/disable individual relationships
- View 100-entry poll history and lag trend chart
- Acknowledge alerts per relationship

### Clusters
- Add Qumulo clusters with hostname, port, API credentials
- Test connectivity before saving
- Auto-discover replication relationships from the Qumulo API
- Bulk import discovered relationships
- Works with self-signed SSL certificates (via internal HTTPS proxy)

### Alerts
- Email alerts for error state and lag threshold breaches
- Per-relationship lag threshold (overrides system default)
- System-wide default lag threshold
- Alert cooldown to prevent alert storms
- Global alert log with pagination and acknowledgment

### User Management
- Admin role: full access to all features
- Viewer role: read-only access to dashboard, relationships, alert log
- Admins can create/edit/delete users and reset passwords
- Users can change their own password

### Settings
- Default lag threshold (minutes)
- Poll interval (seconds, minimum 30)
- Alert cooldown (minutes)
- Full SMTP configuration with connection test
- Alert recipient list (comma-separated emails)
- Test alert button

---

## How the SSL Proxy Works

Qumulo clusters commonly use self-signed SSL certificates. Browsers and Node.js reject these by default. This app runs a lightweight internal proxy (`proxy/proxy.js`) on port 3007 that:

1. Accepts requests from the backend only (bound to `127.0.0.1`)
2. Forwards them to Qumulo clusters with `rejectUnauthorized: false`
3. Returns the response to the backend

The proxy is **never exposed to the internet** — nginx does not route to port 3007, and systemd restricts it to localhost via `IPAddressDeny=any` + `IPAddressAllow=127.0.0.1`.

---

## Qumulo API Endpoints Used

| Endpoint | Purpose |
|---|---|
| `POST /v1/session/login` | Authenticate, get bearer token |
| `GET /v1/replication/source-relationships/` | List source relationships |
| `GET /v1/replication/target-relationships/` | List target relationships |
| `GET /v1/replication/source-relationships/{id}/status` | Get source relationship status |
| `GET /v1/replication/target-relationships/{id}/status` | Get target relationship status |

The API user requires at minimum **read access** to replication configuration and status.

---

## Data Storage

- **Database**: SQLite at `/var/lib/qumulo-monitor/qumulo-monitor.db` (production) or `./data/qumulo-monitor.db` (dev)
- Poll history: last 500 results per relationship retained
- Alert log: all alerts retained indefinitely

---

## Environment Variables

### Backend (`qumulo-monitor.service`)
| Variable | Default | Description |
|---|---|---|
| `BACKEND_PORT` | `3006` | API server port |
| `PROXY_URL` | `http://127.0.0.1:3007` | Internal proxy URL |
| `DB_PATH` | `./data/qumulo-monitor.db` | SQLite database path |
| `JWT_SECRET` | *(required in prod)* | JWT signing secret |
| `FRONTEND_ORIGIN` | `http://localhost:3005` | CORS allowed origin |

### Proxy (`qumulo-proxy.service`)
| Variable | Default | Description |
|---|---|---|
| `PROXY_PORT` | `3007` | Proxy server port |

---

## Service Management

```bash
# Status
systemctl status qumulo-monitor
systemctl status qumulo-proxy

# Logs
journalctl -u qumulo-monitor -f
journalctl -u qumulo-proxy -f

# Restart
systemctl restart qumulo-monitor

# Stop all
systemctl stop qumulo-monitor qumulo-proxy
```

---

## Security Notes

1. **Change the default admin password** immediately after first login.
2. The JWT secret is auto-generated during installation — keep the service file secure.
3. API credentials for Qumulo clusters are stored in the SQLite database. Protect file access accordingly (`chmod 600` the database file).
4. The internal HTTPS proxy (`PORT 3007`) must never be accessible externally. The nginx config does not expose it, and systemd restricts it to localhost.
5. Consider running behind HTTPS in production (see commented nginx SSL block).
