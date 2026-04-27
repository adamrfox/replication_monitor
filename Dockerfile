# ─── Stage 1: Build React frontend ───────────────────────────────────────────
FROM node:18-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ─── Stage 2: Production image ───────────────────────────────────────────────
FROM node:18-alpine

LABEL maintainer="Qumulo Replication Monitor"
LABEL description="Monitors Qumulo replication jobs and sends alerts"

# Install dumb-init for proper signal handling and process supervision
RUN apk add --no-cache dumb-init

WORKDIR /app

# Install backend dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm install --omit=dev

# Install proxy dependencies
COPY proxy/package*.json ./proxy/
RUN cd proxy && npm install --omit=dev

# Copy backend and proxy source
COPY backend/ ./backend/
COPY proxy/ ./proxy/

# Copy built frontend from stage 1
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

# Copy entrypoint script
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# Create data directory for SQLite
RUN mkdir -p /data && chown node:node /data

# Run as non-root
USER node

EXPOSE 3006

ENV NODE_ENV=production \
    BACKEND_PORT=3006 \
    PROXY_PORT=3007 \
    PROXY_URL=http://127.0.0.1:3007 \
    DB_PATH=/data/qumulo-monitor.db \
    FRONTEND_ORIGIN=*

VOLUME ["/data"]

ENTRYPOINT ["dumb-init", "--"]
CMD ["./docker-entrypoint.sh"]
