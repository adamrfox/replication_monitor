'use strict';

const nodemailer = require('nodemailer');
const { getDb } = require('../db/database');
const { v4: uuidv4 } = require('uuid');

function getSettings() {
  const db = getDb();
  const rows = db.prepare('SELECT key, value FROM settings').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
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

async function sendAlertEmail(subject, html, text) {
  const settings = getSettings();
  if (!settings.smtp_host || !settings.alert_recipients) {
    console.log('[Alerts] SMTP not configured, skipping email.');
    return false;
  }

  const recipients = settings.alert_recipients
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);

  if (recipients.length === 0) return false;

  const transporter = createTransporter(settings);
  try {
    await transporter.sendMail({
      from: settings.smtp_from || settings.smtp_user,
      to: recipients.join(', '),
      subject: `[${settings.app_name}] ${subject}`,
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

/**
 * Check cooldown: returns true if we should send this alert.
 */
function shouldSendAlert(db, relationship_id, alert_type, cooldownMinutes) {
  const cutoff = new Date(Date.now() - cooldownMinutes * 60 * 1000).toISOString();
  const recent = db.prepare(`
    SELECT id FROM alert_log
    WHERE relationship_id = ? AND alert_type = ? AND sent_at > ?
    ORDER BY sent_at DESC LIMIT 1
  `).get(relationship_id, alert_type, cutoff);
  return !recent;
}

module.exports = { sendAlertEmail, testSmtpConfig, logAlert, shouldSendAlert };
