'use strict';

const nodemailer = require('nodemailer');
const { getDb } = require('../db/database');
const { v4: uuidv4 } = require('uuid');

function getSettings() {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

/**
 * Resolve a comma-separated string of email addresses and/or group names
 * into a flat deduplicated array of email addresses.
 */
function resolveRecipients(recipientStr) {
  if (!recipientStr) return [];
  const db = getDb();
  const groups = Object.fromEntries(
    db.prepare('SELECT name, addresses FROM recipient_groups').all().map(g => [g.name.toLowerCase(), g.addresses])
  );

  const resolved = new Set();
  for (const entry of recipientStr.split(',').map(e => e.trim()).filter(Boolean)) {
    const lower = entry.toLowerCase();
    if (groups[lower]) {
      // It's a group name — expand it
      for (const addr of groups[lower].split(',').map(e => e.trim()).filter(Boolean)) {
        resolved.add(addr);
      }
    } else {
      // Treat as a raw email address
      resolved.add(entry);
    }
  }
  return [...resolved];
}

function createTransporter(settings) {
  return nodemailer.createTransport({
    host: settings.smtp_host,
    port: parseInt(settings.smtp_port) || 587,
    secure: settings.smtp_secure === 'true',
    auth: settings.smtp_user
      ? { user: settings.smtp_user, pass: settings.smtp_pass }
      : undefined,
    tls: { rejectUnauthorized: false },
  });
}

/**
 * Send an alert email.
 * @param {string} subject
 * @param {string} html
 * @param {string} text
 * @param {string|null} extraRecipients - comma-separated addresses/group names to add
 *                                        alongside the default alert_recipients
 */
async function sendAlertEmail(subject, html, text, extraRecipients = null) {
  const settings = getSettings();
  if (!settings.smtp_host) {
    console.log('[Alerts] SMTP not configured, skipping email.');
    return false;
  }

  // Merge default recipients with any per-relationship extras
  const defaultRecipients = resolveRecipients(settings.alert_recipients);
  const extraResolved = extraRecipients ? resolveRecipients(extraRecipients) : [];

  // Deduplicate — per-relationship recipients are additive to the defaults
  const all = [...new Set([...defaultRecipients, ...extraResolved])];

  if (all.length === 0) {
    console.log('[Alerts] No recipients configured, skipping email.');
    return false;
  }

  const transporter = createTransporter(settings);
  try {
    await transporter.sendMail({
      from: settings.smtp_from || settings.smtp_user,
      to: all.join(', '),
      subject: `[${settings.app_name || 'Qumulo Replication Monitor'}] ${subject}`,
      html,
      text,
    });
    return true;
  } catch (err) {
    console.error('[Alerts] Failed to send email:', err.message);
    return false;
  }
}

async function testSmtpConfig(smtpSettings, testRecipient) {
  const transporter = createTransporter(smtpSettings);
  try {
    await transporter.verify();
    await transporter.sendMail({
      from: smtpSettings.smtp_from || smtpSettings.smtp_user,
      to: testRecipient,
      subject: '[Qumulo Monitor] SMTP Test',
      text: 'SMTP configuration is working correctly.',
      html: '<p>SMTP configuration is working correctly.</p>',
    });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function logAlert(db, { relationship_id, cluster_id, alert_type, message }) {
  db.prepare(`
    INSERT INTO alert_log(id, relationship_id, cluster_id, alert_type, message, sent_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(uuidv4(), relationship_id, cluster_id, alert_type, message, new Date().toISOString());
}

function shouldSendAlert(db, relationship_id, alert_type, cooldownMinutes) {
  const cutoff = new Date(Date.now() - cooldownMinutes * 60 * 1000).toISOString();
  const recent = db.prepare(`
    SELECT id FROM alert_log
    WHERE relationship_id = ? AND alert_type = ? AND sent_at > ?
    ORDER BY sent_at DESC LIMIT 1
  `).get(relationship_id, alert_type, cutoff);
  return !recent;
}

module.exports = { sendAlertEmail, testSmtpConfig, logAlert, shouldSendAlert, resolveRecipients };
