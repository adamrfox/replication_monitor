'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// GET /api/relationships  - list all relationships with latest status
router.get('/', (req, res) => {
  const db = getDb();
  const rels = db.prepare(`
    SELECT r.*,
           c.name as cluster_name, c.host as cluster_host,
           p.status as latest_status,
           p.lag_seconds as latest_lag_seconds,
           p.error_message as latest_error,
           p.raw_data as latest_raw_data,
           p.polled_at as last_polled_at
    FROM replication_relationships r
    JOIN clusters c ON c.id = r.cluster_id
    LEFT JOIN poll_results p ON p.id = (
      SELECT id FROM poll_results
      WHERE relationship_id = r.id
      ORDER BY polled_at DESC LIMIT 1
    )
    ORDER BY c.name, r.display_name
  `).all();
  res.json(rels);
});

// GET /api/relationships/:id  - single relationship with history
router.get('/:id', (req, res) => {
  const db = getDb();
  const rel = db.prepare(`
    SELECT r.*, c.name as cluster_name, c.host as cluster_host
    FROM replication_relationships r
    JOIN clusters c ON c.id = r.cluster_id
    WHERE r.id = ?
  `).get(req.params.id);

  if (!rel) return res.status(404).json({ error: 'Relationship not found' });

  const history = db.prepare(`
    SELECT status, lag_seconds, error_message, raw_data, polled_at
    FROM poll_results WHERE relationship_id = ?
    ORDER BY polled_at DESC LIMIT 100
  `).all(req.params.id);

  const alerts = db.prepare(`
    SELECT * FROM alert_log WHERE relationship_id = ?
    ORDER BY sent_at DESC LIMIT 50
  `).all(req.params.id);

  res.json({ ...rel, history, alerts });
});

// POST /api/relationships  (admin only)
router.post('/', adminOnly, (req, res) => {
  const {
    cluster_id, qumulo_id, display_name, source_path,
    target_host, target_path, direction = 'source',
    lag_threshold_minutes = null, snapshot_queue_threshold = null,
  } = req.body;

  if (!cluster_id || !qumulo_id) {
    return res.status(400).json({ error: 'cluster_id and qumulo_id required' });
  }

  const db = getDb();
  const cluster = db.prepare('SELECT id FROM clusters WHERE id = ?').get(cluster_id);
  if (!cluster) return res.status(404).json({ error: 'Cluster not found' });

  const id = uuidv4();
  db.prepare(`
    INSERT INTO replication_relationships
      (id, cluster_id, qumulo_id, display_name, source_path, target_host, target_path, direction, lag_threshold_minutes, snapshot_queue_threshold)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, cluster_id, qumulo_id, display_name, source_path, target_host, target_path, direction, lag_threshold_minutes, snapshot_queue_threshold);

  res.status(201).json({ id, cluster_id, qumulo_id, display_name, direction });
});

// PUT /api/relationships/:id  (admin only)
router.put('/:id', adminOnly, (req, res) => {
  const db = getDb();
  const rel = db.prepare('SELECT * FROM replication_relationships WHERE id = ?').get(req.params.id);
  if (!rel) return res.status(404).json({ error: 'Relationship not found' });

  const { display_name, source_path, target_host, target_path, lag_threshold_minutes, snapshot_queue_threshold, alert_recipients, enabled } = req.body;

  db.prepare(`
    UPDATE replication_relationships SET
      display_name = COALESCE(?, display_name),
      source_path = COALESCE(?, source_path),
      target_host = COALESCE(?, target_host),
      target_path = COALESCE(?, target_path),
      lag_threshold_minutes = ?,
      snapshot_queue_threshold = ?,
      alert_recipients = ?,
      enabled = COALESCE(?, enabled),
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    display_name, source_path, target_host, target_path,
    lag_threshold_minutes !== undefined ? lag_threshold_minutes : rel.lag_threshold_minutes,
    snapshot_queue_threshold !== undefined ? snapshot_queue_threshold : rel.snapshot_queue_threshold,
    alert_recipients !== undefined ? (alert_recipients || null) : rel.alert_recipients,
    enabled !== undefined ? (enabled ? 1 : 0) : null,
    req.params.id
  );

  res.json(db.prepare('SELECT * FROM replication_relationships WHERE id = ?').get(req.params.id));
});

// DELETE /api/relationships/:id  (admin only)
router.delete('/:id', adminOnly, (req, res) => {
  const db = getDb();
  if (!db.prepare('SELECT id FROM replication_relationships WHERE id = ?').get(req.params.id)) {
    return res.status(404).json({ error: 'Not found' });
  }
  db.prepare('DELETE FROM replication_relationships WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// POST /api/relationships/import-discovered  (admin only)
// Bulk import discovered relationships from a cluster
router.post('/import-discovered', adminOnly, (req, res) => {
  const { cluster_id, relationships } = req.body;
  if (!cluster_id || !Array.isArray(relationships)) {
    return res.status(400).json({ error: 'cluster_id and relationships array required' });
  }

  const db = getDb();
  const insert = db.prepare(`
    INSERT OR IGNORE INTO replication_relationships
      (id, cluster_id, qumulo_id, display_name, source_path, target_host, target_path, direction, replication_mode, replication_enabled, end_reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertMany = db.transaction((rels) => {
    let count = 0;
    for (const r of rels) {
      const replEnabled = typeof r.replication_enabled === 'boolean'
        ? (r.replication_enabled ? 1 : 0)
        : null;
      const endReason = (r.end_reason && r.end_reason !== '') ? r.end_reason : null;
      const result = insert.run(
        uuidv4(),
        cluster_id,
        r.id || r.qumulo_id,
        r.display_name || r.name || r.id,
        r.source_root_path || r.source_path || '',
        r.target_address || r.target_host || '',
        r.target_root_path || r.target_path || '',
        r.direction || 'source',
        r.replication_mode || null,
        replEnabled,
        endReason
      );
      if (result.changes > 0) count++;
    }
    return count;
  });

  const count = insertMany(relationships);
  res.json({ imported: count, total: relationships.length });
});

// GET /api/relationships/:id/alerts  - alert history for a relationship
router.get('/:id/alerts', (req, res) => {
  const db = getDb();
  const alerts = db.prepare(`
    SELECT * FROM alert_log WHERE relationship_id = ?
    ORDER BY sent_at DESC LIMIT 100
  `).all(req.params.id);
  res.json(alerts);
});

// POST /api/relationships/:id/alerts/acknowledge-all  (admin only)
router.post('/:id/alerts/acknowledge-all', adminOnly, (req, res) => {
  const db = getDb();
  const result = db.prepare(`
    UPDATE alert_log
    SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
    WHERE relationship_id = ? AND acknowledged = 0
  `).run(new Date().toISOString(), req.user.username, req.params.id);
  res.json({ acknowledged: result.changes });
});

// POST /api/relationships/:id/alerts/:alertId/acknowledge  (admin only)
router.post('/:id/alerts/:alertId/acknowledge', adminOnly, (req, res) => {
  const db = getDb();
  db.prepare(`
    UPDATE alert_log SET acknowledged = 1, acknowledged_at = CURRENT_TIMESTAMP, acknowledged_by = ?
    WHERE id = ?
  `).run(req.user.username, req.params.alertId);
  res.json({ acknowledged: true });
});

module.exports = router;
