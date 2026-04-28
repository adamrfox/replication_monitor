'use strict';

const express = require('express');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const { testSmtpConfig, sendAlertEmail } = require('../services/alertService');
const { restartPoller } = require('../services/pollerService');

const router = express.Router();
// GET /api/settings/public — no auth required, returns only non-sensitive display settings
router.get('/public', (req, res) => {
  const db = getDb();
  const row = db.prepare("SELECT value FROM settings WHERE key = 'app_name'").get();
  res.json({ app_name: row?.value || 'Qumulo Replication Monitor' });
});

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
  'alert_retention_days',
  'job_stats_retention_days',
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

// POST /api/settings/alerts/acknowledge-all  (admin only)
router.post('/alerts/acknowledge-all', adminOnly, (req, res) => {
  const db = getDb();
  const result = db.prepare(`
    UPDATE alert_log
    SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
    WHERE acknowledged = 0
  `).run(new Date().toISOString(), req.user.username);
  res.json({ acknowledged: result.changes });
});

// POST /api/settings/alerts/purge  (admin only)
// Purge alerts older than the retention period (or a custom number of days)
router.post('/alerts/purge', adminOnly, (req, res) => {
  const db = getDb();
  const settings = Object.fromEntries(
    db.prepare('SELECT key, value FROM settings').all().map(r => [r.key, r.value])
  );
  const days = parseInt(req.body.days) || parseInt(settings.alert_retention_days) || 90;
  const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const result = db.prepare('DELETE FROM alert_log WHERE sent_at < ?').run(cutoff);
  res.json({ deleted: result.changes, older_than_days: days });
});

// POST /api/settings/alerts/purge-all  (admin only)
// Delete ALL alert log entries
router.post('/alerts/purge-all', adminOnly, (req, res) => {
  const db = getDb();
  const result = db.prepare('DELETE FROM alert_log').run();
  res.json({ deleted: result.changes });
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
