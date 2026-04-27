# Qumulo Replication Monitor

A self-hosted web application that monitors Qumulo replication jobs, reports their status, and sends email alerts when jobs enter an error state, fall behind a configurable lag threshold, or exceed a snapshot queue depth.

---

## Table of Contents

- [Architecture](#architecture)
- [Installation — Native (systemd)](#installation--native-systemd)
- [Installation — Docker](#installation--docker)
- [First-Time Setup](#first-time-setup)
- [Nginx Configuration](#nginx-configuration)
- [Features](#features)
- [Status Reference](#status-reference)
- [Qumulo API Notes](#qumulo-api-notes)
- [Environment Variables](#environment-variables)
- [Service Management](#service-management)
- [Security Notes](#security-notes)

---

## Architecture

```
Browser
  │
  ▼
Nginx (port 3008)              ← Single public-facing port
  ├── /api/*  ──────────────►  Backend API  (port 3006, Express + SQLite)
  │                                  │
  │                                  │  HTTP (localhost only)
  │                                  ▼
  │                             HTTPS Proxy  (port 3007, internal)
  │                                  │  Bypasses SSL cert validation
  │                                  ▼
  │                             Qumulo Clusters (any port, HTTP or HTTPS)
  │
  └── /*  ────────────────────► React SPA (served by backend)
```

### Port Assignment

| Service       | Port | Notes                                      |
|---------------|------|--------------------------------------------|
| Nginx (app)   | 3008 | Only public-facing port                    |
| Backend API   | 3006 | Express; also serves built frontend        |
| HTTPS Proxy   | 3007 | Internal only; bound to 127.0.0.1          |
| Frontend dev  | 3005 | Development only (Vite)                    |

---

## Installation — Native (systemd)

Runs directly on the host OS as systemd services. Best when you want tight integration with the existing system or are already running other Node.js apps on the same machine.

### Prerequisites

- Ubuntu 20.04+ (or similar Linux)
- Node.js 18+
- npm
- nginx

```bash
# Install Node.js 18 if needed
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs nginx
```

### Install

```bash
# Clone or extract the project
cd /var/www
git clone <repo-url> replication_monitor
cd replication_monitor

# Run the installer (requires root)
chmod +x install.sh
sudo ./install.sh
```

The installer will:
1. Check Node.js version
2. Install npm dependencies for backend, proxy, and frontend
3. Build the React frontend
4. Generate a random JWT secret
5. Install and start systemd services (`qumulo-proxy`, `qumulo-monitor`)
6. Install and reload the nginx configuration

Access the app at `http://<your-server>:3008`

### Manual Nginx Setup

If you use a single nginx config file, append the following server block:

```nginx
server {
    listen 3008;
    server_name _;

    proxy_connect_timeout   30s;
    proxy_send_timeout      60s;
    proxy_read_timeout      60s;

    location /api/ {
        proxy_pass         http://127.0.0.1:3006;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   Connection        "";
    }

    location /health {
        proxy_pass http://127.0.0.1:3006/health;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }

    location / {
        proxy_pass         http://127.0.0.1:3006;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   Connection        "";
    }
}
```

Then reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Development Mode

```bash
chmod +x dev.sh
./dev.sh
# Open http://localhost:3005
```

### Service Management

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

### Data Location

```
/var/lib/qumulo-monitor/qumulo-monitor.db
```

---

## Installation — Docker

Runs as a single container. Best for isolated deployments, easy upgrades, or environments where Docker is already in use.

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2 (included with Docker Desktop; on Linux: `sudo apt install docker-compose-plugin`)

```bash
# Verify
docker --version
docker compose version
```

### Configure

Before building, edit `docker-compose.yml` and set a persistent JWT secret:

```bash
# Generate a secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste the output into `docker-compose.yml`:

```yaml
environment:
  JWT_SECRET: "paste-your-generated-secret-here"
```

If you skip this, a random secret is generated on each start and all sessions are invalidated on container restart.

### Build and Start

```bash
# Build the image (first time or after code changes)
docker compose build

# Start in the background
docker compose up -d

# Check status
docker compose ps

# Follow logs
docker compose logs -f
```

Access the app at `http://<your-server>:3008`

### Nginx Configuration (Docker)

When running Docker on the same machine as nginx, use `nginx-docker.conf`. The container maps its internal port 3006 to host port 3008, and nginx proxies to that:

```nginx
server {
    listen 3008;
    server_name _;

    location /api/ {
        proxy_pass http://127.0.0.1:3008;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
    }

    location / {
        proxy_pass http://127.0.0.1:3008;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
    }
}
```

> **Note:** If you're running both the native systemd install and Docker on the same machine, change the Docker host port in `docker-compose.yml` to avoid conflicts:
> ```yaml
> ports:
>   - "3009:3006"   # Docker on 3009, systemd on 3008
> ```

### Upgrading (Docker)

```bash
# Pull latest code, rebuild, and restart — data is preserved on the volume
git pull
docker compose build
docker compose up -d
```

### Stopping and Removing

```bash
# Stop container (data preserved)
docker compose down

# Stop and remove data volume (destructive)
docker compose down -v
```

### Data Location (Docker)

SQLite lives on a named Docker volume:

```bash
# Inspect volume location
docker volume inspect qumulo-monitor_qumulo-monitor-data

# Backup
docker run --rm \
  -v qumulo-monitor_qumulo-monitor-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/qumulo-monitor-backup.tar.gz /data
```

---

## First-Time Setup

Regardless of installation method, after accessing the app for the first time:

1. **Log in** with `admin` / `admin`
2. **Change the admin password immediately** — Users → change password
3. **Add a Cluster** — Clusters → Add Cluster
   - Enter hostname/IP, port (default 8000), API credentials
   - Click ⚡ Test to verify connectivity
   - Click ↓ Discover to find replication relationships
   - Select and import the relationships to monitor
4. **Configure alerts** — Settings → Email / SMTP
   - Enter SMTP server details
   - Set alert recipients (or create Recipient Groups first)
   - Send a test email to verify
5. **Set thresholds** — Settings → General
   - Default lag threshold (minutes) — for continuous replication
   - Default snapshot queue threshold — for snapshot-policy replication
   - Poll interval, alert cooldown, retention periods

---

## Features

### Dashboard
- Status cards for all monitored relationships
- Filter by status: OK, Running, Lagging, Error, Disabled, Ended, Unknown
- Auto-refreshes every 30 seconds
- Click stat cards to filter the relationship grid

### Relationships
- Table view with live status, lag, and queue depth
- Per-relationship detail with configuration, live status, and active transfer progress
- Job Stats tab with synchronized time-series charts:
  - Lag trend (continuous relationships)
  - Data moved, throughput, files transferred (captured during active jobs)
  - Adjustable time range with presets (1h, 6h, 12h, 1d, 7d, 30d, 90d)
  - Export to CSV or PDF
- Editable display name, lag threshold, snapshot queue threshold, alert recipients

### Clusters
- Add/edit/delete Qumulo clusters
- Connection testing before saving
- Auto-discovery of relationships with real paths (fetched from status API)
- Filters already-imported relationships from discover results
- Works with self-signed SSL certificates via internal HTTPS proxy

### Alerts
- Email alerts for: error state, lag threshold exceeded, snapshot queue exceeded
- Per-relationship alert recipient override (additive to defaults)
- Recipient groups — named groups of addresses usable anywhere
- Alert cooldown to prevent storms
- Global alert log with pagination and acknowledgment
- Acknowledge All button (global and per-relationship)
- Configurable retention with manual purge controls

### User Management
- Admin role: full access
- Viewer role: read-only dashboard, relationships, alert log
- Admins manage users; users can change their own password

### Settings
- General: thresholds, poll interval, cooldown, retention periods
- Email / SMTP: full configuration with test send
- Alert Recipients: default recipients with group name support
- Recipient Groups: named address lists
- Maintenance: manual alert log purge (by age or all)

---

## Status Reference

| Status | Meaning |
|--------|---------|
| **OK** | Established, enabled, within lag/queue threshold |
| **Running** | Actively transferring data (caught mid-job by poller) |
| **Lagging** | Idle but recovery point older than lag threshold, or queue exceeds max |
| **Error** | Job faulted, cannot reach target, or state is DISCONNECTED |
| **Disabled** | `replication_enabled: false` on the cluster |
| **Ended** | Relationship permanently terminated (`end_reason` set) |
| **Unknown** | Not yet polled or state unrecognized |

### Lag / Queue Display

Continuous relationships show lag as time (minutes) with a color-coded progress bar:
- 🟢 Green — below 80% of threshold
- 🟡 Yellow — 80–100% of threshold
- 🔴 Red — at or above threshold

Snapshot-policy relationships show `queued / max` with the same color logic. Disabled snapshot relationships show time-based lag from `recovery_point` regardless, since the queue is always 0 when disabled.

---

## Qumulo API Notes

### API Version

The tool uses v2 API paths (`/v2/replication/...`) with automatic fallback to v1 for older clusters.

### Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/session/login` | Authenticate, get bearer token |
| `GET /v2/replication/source-relationships/` | List source relationships |
| `GET /v2/replication/target-relationships/` | List target relationships |
| `GET /v2/replication/source-relationships/status/` | Bulk source status (all at once) |
| `GET /v2/replication/target-relationships/status/` | Bulk target status (all at once) |
| `GET /v2/replication/source-relationships/{id}/status` | Per-relationship status (discovery) |

### Replication Modes

| API Value | Behavior |
|-----------|----------|
| `REPLICATION_CONTINUOUS` | Time-based lag monitoring |
| `REPLICATION_SNAPSHOT_POLICY` | Queue depth monitoring |
| `REPLICATION_SNAPSHOT_POLICY_WITH_CONTINUOUS` | Treated as continuous (time-based lag) |

### SSL Certificates

Qumulo clusters commonly use self-signed certificates. The internal HTTPS proxy bypasses certificate validation (`rejectUnauthorized: false`) so the tool works with any cluster. The proxy is bound to `127.0.0.1` only and is never accessible externally.

---

## Environment Variables

### Backend

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_PORT` | `3006` | API server port |
| `PROXY_URL` | `http://127.0.0.1:3007` | Internal proxy URL |
| `DB_PATH` | `./data/qumulo-monitor.db` | SQLite database path |
| `JWT_SECRET` | *(required in prod)* | JWT signing secret — set a stable value |
| `FRONTEND_ORIGIN` | `*` | CORS allowed origin |
| `NODE_ENV` | `production` | Node environment |

### Proxy

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `3007` | Proxy server port |

---

## Security Notes

1. **Change the default admin password** immediately after first login
2. **Set a stable `JWT_SECRET`** — without it, all sessions are invalidated on restart
3. Qumulo API credentials are stored in the SQLite database — protect the database file
4. The internal HTTPS proxy (port 3007) is bound to `127.0.0.1` only and must never be exposed externally
5. Consider running behind HTTPS in production — see the nginx SSL block in `nginx/qumulo-monitor.conf`
6. The Docker image runs as the non-root `node` user

---

## Firewall

Only **port 3008** needs to be open for external access:

```bash
# ufw
sudo ufw allow 3008/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=3008/tcp
sudo firewall-cmd --reload
```

Ports 3006 and 3007 are internal only and must not be opened externally.
