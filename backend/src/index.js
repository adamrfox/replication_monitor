'use strict';

const express = require('express');
const cors = require('cors');
const path = require('path');

const authRoutes = require('./routes/auth');
const clusterRoutes = require('./routes/clusters');
const relationshipRoutes = require('./routes/relationships');
const settingsRoutes = require('./routes/settings');
const { startPoller } = require('./services/pollerService');

const app = express();
const PORT = process.env.BACKEND_PORT || 3006;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:3005',
  credentials: true,
}));
app.use(express.json({ limit: '5mb' }));

// Request logging
app.use((req, _res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/clusters', clusterRoutes);
app.use('/api/relationships', relationshipRoutes);
app.use('/api/settings', settingsRoutes);

// Health check
app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'qumulo-monitor-api', ts: new Date().toISOString() }));

// Serve frontend in production
const frontendBuild = path.join(__dirname, '../../frontend/dist');
app.use(express.static(frontendBuild));
app.get('*', (_req, res) => {
  res.sendFile(path.join(frontendBuild, 'index.html'), (err) => {
    if (err) res.status(404).json({ error: 'Not found' });
  });
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('[Error]', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`[API] Qumulo Monitor backend listening on http://localhost:${PORT}`);
  startPoller();
});

module.exports = app;
