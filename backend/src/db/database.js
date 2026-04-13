'use strict';

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../../data/qumulo-monitor.db');

let db;

function getDb() {
  if (!db) {
    const fs = require('fs');
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',   -- 'admin' | 'viewer'
      email TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    );

    CREATE TABLE IF NOT EXISTS clusters (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 8000,
      use_ssl INTEGER NOT NULL DEFAULT 1,
      api_username TEXT NOT NULL,
      api_password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS replication_relationships (
      id TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
      qumulo_id TEXT,                        -- ID from Qumulo API
      display_name TEXT,
      source_path TEXT,
      target_host TEXT,
      target_path TEXT,
      direction TEXT,                        -- 'source' | 'target'
      replication_mode TEXT,                 -- 'REPLICATION_CONTINUOUS' | 'REPLICATION_SNAPSHOT_POLICY'
      lag_threshold_minutes INTEGER,         -- per-relationship override (NULL = use default)
      snapshot_queue_threshold INTEGER,      -- for snapshot-mode rels: alert if queued > this (NULL = use default)
      replication_enabled INTEGER,          -- 0/1 as reported by Qumulo API (NULL = unknown)
      end_reason TEXT,                       -- populated when relationship has been ended on the cluster
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS alert_log (
      id TEXT PRIMARY KEY,
      relationship_id TEXT,
      cluster_id TEXT,
      alert_type TEXT NOT NULL,             -- 'error' | 'lag' | 'recovery'
      message TEXT NOT NULL,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      acknowledged INTEGER DEFAULT 0,
      acknowledged_at DATETIME,
      acknowledged_by TEXT
    );

    CREATE TABLE IF NOT EXISTS poll_results (
      id TEXT PRIMARY KEY,
      cluster_id TEXT NOT NULL,
      relationship_id TEXT NOT NULL,
      status TEXT,
      lag_seconds INTEGER,
      error_message TEXT,
      raw_data TEXT,
      polled_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_poll_results_rel ON poll_results(relationship_id, polled_at DESC);
    CREATE INDEX IF NOT EXISTS idx_alert_log_rel ON alert_log(relationship_id, sent_at DESC);
  `)

  // Migrations for existing installs
  const cols = db.prepare("PRAGMA table_info(replication_relationships)").all().map(c => c.name);
  if (!cols.includes('snapshot_queue_threshold')) {
    db.exec("ALTER TABLE replication_relationships ADD COLUMN snapshot_queue_threshold INTEGER");
  }
  if (!cols.includes('replication_mode')) {
    db.exec("ALTER TABLE replication_relationships ADD COLUMN replication_mode TEXT");
  }
  if (!cols.includes('replication_enabled')) {
    db.exec("ALTER TABLE replication_relationships ADD COLUMN replication_enabled INTEGER");
  }
  if (!cols.includes('end_reason')) {
    db.exec("ALTER TABLE replication_relationships ADD COLUMN end_reason TEXT");
  }

  // Insert default settings if not present
  const defaults = {
    default_lag_threshold_minutes: '60',
    alert_retention_days: '90',
    default_snapshot_queue_threshold: '3',
    poll_interval_seconds: '60',
    alert_cooldown_minutes: '30',
    smtp_host: '',
    smtp_port: '587',
    smtp_secure: 'false',
    smtp_user: '',
    smtp_pass: '',
    smtp_from: '',
    alert_recipients: '',
    app_name: 'Qumulo Replication Monitor',
  };

  const upsert = db.prepare(
    `INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)`
  );
  for (const [k, v] of Object.entries(defaults)) {
    upsert.run(k, v);
  }

  // Create default admin if no users exist
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (userCount.c === 0) {
    const { v4: uuidv4 } = require('uuid');
    const hash = bcrypt.hashSync('admin', 10);
    db.prepare(
      `INSERT INTO users(id, username, password_hash, role, email) VALUES (?, 'admin', ?, 'admin', '')`
    ).run(uuidv4(), hash);
    console.log('[DB] Default admin user created (username: admin, password: admin)');
  }
}

module.exports = { getDb };
