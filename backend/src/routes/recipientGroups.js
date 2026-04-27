'use strict';

const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly } = require('../middleware/auth');

const router = express.Router();
router.use(authMiddleware);

// GET /api/recipient-groups
router.get('/', (req, res) => {
  const db = getDb();
  res.json(db.prepare('SELECT * FROM recipient_groups ORDER BY name').all());
});

// POST /api/recipient-groups  (admin only)
router.post('/', adminOnly, (req, res) => {
  const { name, description = '', addresses } = req.body;
  if (!name || !addresses) return res.status(400).json({ error: 'name and addresses required' });

  const db = getDb();
  if (db.prepare('SELECT id FROM recipient_groups WHERE name = ?').get(name)) {
    return res.status(409).json({ error: 'Group name already exists' });
  }
  const id = uuidv4();
  db.prepare(`INSERT INTO recipient_groups(id, name, description, addresses) VALUES (?, ?, ?, ?)`)
    .run(id, name.trim(), description.trim(), addresses.trim());
  res.status(201).json({ id, name, description, addresses });
});

// PUT /api/recipient-groups/:id  (admin only)
router.put('/:id', adminOnly, (req, res) => {
  const db = getDb();
  const group = db.prepare('SELECT * FROM recipient_groups WHERE id = ?').get(req.params.id);
  if (!group) return res.status(404).json({ error: 'Group not found' });

  const { name, description, addresses } = req.body;

  // Check name uniqueness if changing
  if (name && name !== group.name) {
    if (db.prepare('SELECT id FROM recipient_groups WHERE name = ? AND id != ?').get(name, req.params.id)) {
      return res.status(409).json({ error: 'Group name already exists' });
    }
  }

  db.prepare(`
    UPDATE recipient_groups SET
      name        = COALESCE(?, name),
      description = COALESCE(?, description),
      addresses   = COALESCE(?, addresses),
      updated_at  = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(name?.trim() || null, description?.trim() ?? null, addresses?.trim() || null, req.params.id);

  res.json(db.prepare('SELECT * FROM recipient_groups WHERE id = ?').get(req.params.id));
});

// DELETE /api/recipient-groups/:id  (admin only)
router.delete('/:id', adminOnly, (req, res) => {
  const db = getDb();
  if (!db.prepare('SELECT id FROM recipient_groups WHERE id = ?').get(req.params.id)) {
    return res.status(404).json({ error: 'Group not found' });
  }
  db.prepare('DELETE FROM recipient_groups WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

module.exports = router;
