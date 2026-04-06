'use strict';

const express = require('express');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const { testSmtpConfig, sendAlertEmail } = require('../services/alertService');
const { restartPoller } = require('../services/pollerService');

const router = express.Router();
router.use(authMiddleware);

const PUBLIC_SETTINGS = [
  'default_lag_threshold_minutes',
  'default_snapshot_queue_threshold',
  'poll_interval_seconds',
  'app_name',
];

const ADMIN_SETTINGS = [
  ...PUBLIC_SETTINGS,
  'alert_cooldown_minutes',
  'smtp_host',
  'smtp_port',
  'smtp_secure',
  'smtp_user',
  'smtp_from',
  'alert_recipients',
  // smtp_pass is write-only, never returned
];

// GET /api/settings
router.get('/', (req, res) => {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const all = Object.fromEntries(rows.map((r) => [r.key, r.value]));

  const allowedKeys = req.user.role === 'admin' ? ADMIN_SETTINGS : PUBLIC_SETTINGS;
  const filtered = {};
  for (const k of allowedKeys) {
    if (k in all) filtered[k] = all[k];
  }
  res.json(filtered);
});

// PUT /api/settings  (admin only)
router.put('/', adminOnly, (req, res) => {
  const db = getDb();
  const allowed = new Set(ADMIN_SETTINGS.concat(['smtp_pass', 'alert_cooldown_minutes']));
  const upsert = db.prepare(
    `INSERT INTO settings(key, value, updated_at) VALUES(?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  );

  const updates = db.transaction((body) => {
    let count = 0;
    for (const [k, v] of Object.entries(body)) {
      if (allowed.has(k)) {
        upsert.run(k, String(v));
        count++;
      }
    }
    return count;
  });

  const count = updates(req.body);

  // Restart poller if interval changed
  if (req.body.poll_interval_seconds) {
    restartPoller();
  }

  res.json({ updated: count });
});

// POST /api/settings/test-smtp  (admin only)
router.post('/test-smtp', adminOnly, async (req, res) => {
  const { test_recipient, ...smtpSettings } = req.body;
  if (!test_recipient) return res.status(400).json({ error: 'test_recipient required' });

  // If smtp_pass not provided, load from DB
  if (!smtpSettings.smtp_pass) {
    const db = getDb();
    const row = db.prepare("SELECT value FROM settings WHERE key = 'smtp_pass'").get();
    if (row) smtpSettings.smtp_pass = row.value;
  }

  const result = await testSmtpConfig(smtpSettings, test_recipient);
  res.json(result);
});

// GET /api/settings/alerts  - global alert log
router.get('/alerts', (req, res) => {
  const db = getDb();
  const page = Math.max(0, parseInt(req.query.page) || 0);
  const limit = Math.min(100, parseInt(req.query.limit) || 50);

  const total = db.prepare("SELECT COUNT(*) as c FROM alert_log").get().c;
  const alerts = db.prepare(`
    SELECT a.*, r.display_name as relationship_name, c.name as cluster_name
    FROM alert_log a
    LEFT JOIN replication_relationships r ON r.id = a.relationship_id
    LEFT JOIN clusters c ON c.id = a.cluster_id
    ORDER BY a.sent_at DESC
    LIMIT ? OFFSET ?
  `).all(limit, page * limit);

  res.json({ alerts, total, page, limit });
});

// POST /api/settings/send-test-alert  (admin only)
router.post('/send-test-alert', adminOnly, async (req, res) => {
  const sent = await sendAlertEmail(
    'Test Alert',
    '<h2>Test Alert</h2><p>This is a test alert from the Qumulo Replication Monitor.</p>',
    'Test alert from Qumulo Replication Monitor.'
  );
  res.json({ sent });
});

module.exports = router;
