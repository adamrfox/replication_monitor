'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { getDb } = require('../db/database');
const { authMiddleware, adminOnly, signToken } = require('../middleware/auth');

const router = express.Router();

// POST /api/auth/login
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);

  const token = signToken({ id: user.id, username: user.username, role: user.role });
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, email: user.email },
  });
});

// GET /api/auth/me
router.get('/me', authMiddleware, (req, res) => {
  const db = getDb();
  const user = db.prepare('SELECT id, username, role, email, created_at, last_login FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// GET /api/auth/users  (admin only)
router.get('/users', authMiddleware, adminOnly, (req, res) => {
  const db = getDb();
  const users = db.prepare('SELECT id, username, role, email, created_at, last_login FROM users ORDER BY created_at').all();
  res.json(users);
});

// POST /api/auth/users  (admin only)
router.post('/users', authMiddleware, adminOnly, (req, res) => {
  const { username, password, role = 'viewer', email = '' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!['admin', 'viewer'].includes(role)) return res.status(400).json({ error: 'role must be admin or viewer' });

  const db = getDb();
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already exists' });

  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users(id, username, password_hash, role, email) VALUES (?, ?, ?, ?, ?)').run(id, username, hash, role, email);
  res.status(201).json({ id, username, role, email });
});

// PUT /api/auth/users/:id  (admin only)
router.put('/users/:id', authMiddleware, adminOnly, (req, res) => {
  const db = getDb();
  const { password, role, email } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (role && !['admin', 'viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  // Prevent demoting the last admin
  if (role === 'viewer' && user.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get();
    if (adminCount.c <= 1) return res.status(400).json({ error: 'Cannot demote the last admin' });
  }

  const updates = [];
  const params = [];
  if (password) { updates.push('password_hash = ?'); params.push(bcrypt.hashSync(password, 10)); }
  if (role) { updates.push('role = ?'); params.push(role); }
  if (email !== undefined) { updates.push('email = ?'); params.push(email); }

  if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });

  params.push(req.params.id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  const updated = db.prepare('SELECT id, username, role, email, created_at, last_login FROM users WHERE id = ?').get(req.params.id);
  res.json(updated);
});

// DELETE /api/auth/users/:id  (admin only)
router.delete('/users/:id', authMiddleware, adminOnly, (req, res) => {
  const db = getDb();
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.role === 'admin') {
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'admin'").get();
    if (adminCount.c <= 1) return res.status(400).json({ error: 'Cannot delete the last admin' });
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ deleted: true });
});

// PUT /api/auth/change-password (self-service)
router.put('/change-password', authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'Both passwords required' });
  if (new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(current_password, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(new_password, 10), req.user.id);
  res.json({ success: true });
});

module.exports = router;
