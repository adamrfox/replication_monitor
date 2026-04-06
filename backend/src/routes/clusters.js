'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly } = require('../middleware/auth');
const { testClusterConnection, getSourceRelationships, getTargetRelationships, getSourceRelationshipStatus, getTargetRelationshipStatus, qumuloLogin } = require('../services/qumuloService');

const router = express.Router();
router.use(authMiddleware);

// GET /api/clusters
router.get('/', (req, res) => {
  const db = getDb();
  // Don't expose passwords to viewers
  const cols = req.user.role === 'admin'
    ? 'id, name, host, port, use_ssl, api_username, created_at, updated_at'
    : 'id, name, host, port, use_ssl, created_at';
  const clusters = db.prepare(`SELECT ${cols} FROM clusters ORDER BY name`).all();
  res.json(clusters);
});

// POST /api/clusters  (admin only)
router.post('/', adminOnly, (req, res) => {
  const { name, host, port = 8000, use_ssl = true, api_username, api_password } = req.body;
  if (!name || !host || !api_username || !api_password) {
    return res.status(400).json({ error: 'name, host, api_username, api_password required' });
  }
  const db = getDb();
  const id = uuidv4();
  db.prepare(`
    INSERT INTO clusters(id, name, host, port, use_ssl, api_username, api_password)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, host, port, use_ssl ? 1 : 0, api_username, api_password);
  res.status(201).json({ id, name, host, port, use_ssl });
});

// PUT /api/clusters/:id  (admin only)
router.put('/:id', adminOnly, (req, res) => {
  const db = getDb();
  const cluster = db.prepare('SELECT * FROM clusters WHERE id = ?').get(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'Cluster not found' });

  const { name, host, port, use_ssl, api_username, api_password } = req.body;
  db.prepare(`
    UPDATE clusters SET
      name = COALESCE(?, name),
      host = COALESCE(?, host),
      port = COALESCE(?, port),
      use_ssl = COALESCE(?, use_ssl),
      api_username = COALESCE(?, api_username),
      api_password = COALESCE(?, api_password),
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(name, host, port, use_ssl !== undefined ? (use_ssl ? 1 : 0) : null, api_username, api_password, req.params.id);

  res.json(db.prepare('SELECT id, name, host, port, use_ssl, api_username, created_at, updated_at FROM clusters WHERE id = ?').get(req.params.id));
});

// DELETE /api/clusters/:id  (admin only)
router.delete('/:id', adminOnly, (req, res) => {
  const db = getDb();
  const cluster = db.prepare('SELECT id FROM clusters WHERE id = ?').get(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'Cluster not found' });
  db.prepare('DELETE FROM clusters WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// POST /api/clusters/:id/test  (admin only)
router.post('/:id/test', adminOnly, async (req, res) => {
  const db = getDb();
  const cluster = db.prepare('SELECT * FROM clusters WHERE id = ?').get(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'Cluster not found' });
  const result = await testClusterConnection(cluster);
  res.json(result);
});

// POST /api/clusters/test-new  (admin only) - test before saving
router.post('/test-new', adminOnly, async (req, res) => {
  const { host, port = 8000, use_ssl = true, api_username, api_password } = req.body;
  if (!host || !api_username || !api_password) {
    return res.status(400).json({ error: 'host, api_username, api_password required' });
  }
  const result = await testClusterConnection({ host, port, use_ssl: use_ssl ? 1 : 0, api_username, api_password });
  res.json(result);
});

// GET /api/clusters/:id/discover  (admin only) - discover relationships from cluster
router.get('/:id/discover', adminOnly, async (req, res) => {
  const db = getDb();
  const cluster = db.prepare('SELECT * FROM clusters WHERE id = ?').get(req.params.id);
  if (!cluster) return res.status(404).json({ error: 'Cluster not found' });

  try {
    // Login once and reuse the token for all status calls
    const token = await qumuloLogin(cluster);

    // Get the qumulo_ids already imported for this cluster so we can exclude them
    const existingIds = new Set(
      db.prepare('SELECT qumulo_id FROM replication_relationships WHERE cluster_id = ?')
        .all(req.params.id)
        .map(r => r.qumulo_id)
    );

    const [sourceResult, targetResult] = await Promise.allSettled([
      getSourceRelationships(cluster),
      getTargetRelationships(cluster),
    ]);

    const toArray = (val) => {
      if (!val) return [];
      if (Array.isArray(val)) return val;
      if (Array.isArray(val.entries)) return val.entries;
      const arrVal = Object.values(val).find(v => Array.isArray(v));
      if (arrVal) return arrVal;
      return [];
    };

    // Collect base relationships, excluding already-imported ones
    const base = [];
    if (sourceResult.status === 'fulfilled') {
      for (const r of toArray(sourceResult.value)) {
        if (!existingIds.has(r.id)) base.push({ ...r, direction: 'source' });
      }
    } else {
      console.error('[Discover] Source relationships error:', sourceResult.reason?.message);
    }
    if (targetResult.status === 'fulfilled') {
      for (const r of toArray(targetResult.value)) {
        if (!existingIds.has(r.id)) base.push({ ...r, direction: 'target' });
      }
    } else {
      console.error('[Discover] Target relationships error:', targetResult.reason?.message);
    }

    // Fetch status for each relationship to get real paths and replication mode.
    // Run in parallel with a concurrency cap to avoid hammering the cluster.
    const CONCURRENCY = 5;
    const relationships = [];
    for (let i = 0; i < base.length; i += CONCURRENCY) {
      const chunk = base.slice(i, i + CONCURRENCY);
      const statusResults = await Promise.allSettled(
        chunk.map(r =>
          r.direction === 'target'
            ? getTargetRelationshipStatus(cluster, r.id)
            : getSourceRelationshipStatus(cluster, r.id)
        )
      );
      for (let j = 0; j < chunk.length; j++) {
        const r = chunk[j];
        const statusResult = statusResults[j];
        if (statusResult.status === 'fulfilled') {
          const s = statusResult.value;
          relationships.push({
            ...r,
            source_root_path:    s.source_root_path    || r.source_root_path || '',
            target_root_path:    s.target_root_path    || r.target_root_path || '',
            target_address:      s.target_address      || r.target_address   || '',
            target_port:         s.target_port         || r.target_port      || '',
            source_cluster_name: s.source_cluster_name || '',
            target_cluster_name: s.target_cluster_name || '',
            replication_mode:    s.replication_mode    || r.replication_mode || '',
            replication_enabled: typeof s.replication_enabled === 'boolean' ? s.replication_enabled : r.replication_enabled,
            end_reason: (s.end_reason && s.end_reason !== '') ? s.end_reason : null,
            display_name: (s.source_root_path && s.target_root_path)
              ? `${s.source_cluster_name || cluster.name}:${s.source_root_path} → ${s.target_cluster_name || s.target_address || ''}:${s.target_root_path}`
              : r.id,
          });
        } else {
          console.error('[Discover] Status fetch failed for', r.id, statusResult.reason?.message);
          relationships.push({ ...r, display_name: r.id });
        }
      }
    }

    res.json({ relationships });
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

module.exports = router;
