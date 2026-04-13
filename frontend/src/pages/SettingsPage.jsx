import { useState, useEffect, useCallback } from 'react';
import { Settings, Mail, Clock, Bell, Send, CheckCircle } from 'lucide-react';
import { api } from '../api/client';
import { useToast } from '../hooks/useToast';
import { Spinner } from '../components/shared';

export default function SettingsPage() {
  const { toast } = useToast();
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [tab, setTab] = useState('general');

  const load = useCallback(async () => {
    const data = await api.settings();
    setSettings(data); setLoading(false);
  }, []);
  useEffect(() => { load(); }, [load]);

  const set = (k, v) => setSettings(s => ({ ...s, [k]: v }));

  const handleSave = async (keys) => {
    setSaving(true);
    try {
      const payload = keys ? Object.fromEntries(keys.map(k => [k, settings[k] ?? ''])) : settings;
      await api.updateSettings(payload);
      toast('Settings saved', 'success');
    } catch (e) { toast(e.message, 'error'); }
    setSaving(false);
  };

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>;

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Settings</div>
          <div className="page-subtitle">System configuration and alert setup</div>
        </div>
      </div>
      <div className="page-body">
        <div className="tabs">
          {[['general', 'General'], ['smtp', 'Email / SMTP'], ['alerts', 'Alert Recipients'], ['maintenance', 'Maintenance']].map(([id, label]) => (
            <button key={id} className={`tab-btn ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>

        {tab === 'general' && (
          <div className="card" style={{ maxWidth: 600 }}>
            <div className="card-header"><span className="card-title"><Settings size={14} /> General</span></div>
            <div className="card-body">
              <div className="form-group">
                <label className="form-label">Application Name</label>
                <input className="form-control" value={settings.app_name || ''} onChange={e => set('app_name', e.target.value)} />
              </div>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label">Default Lag Threshold (minutes)</label>
                  <input className="form-control" type="number" min="1" value={settings.default_lag_threshold_minutes ?? ''} onChange={e => set('default_lag_threshold_minutes', e.target.value)} />
                  <div className="form-hint">For continuous replication: alert when lag exceeds this. Can be overridden per relationship.</div>
                </div>
                <div className="form-group">
                  <label className="form-label">Default Snapshot Queue Threshold</label>
                  <input className="form-control" type="number" min="1" value={settings.default_snapshot_queue_threshold ?? ''} onChange={e => set('default_snapshot_queue_threshold', e.target.value)} />
                  <div className="form-hint">For snapshot-policy replication: alert when queued snapshots exceed this. Can be overridden per relationship.</div>
                </div>
                <div className="form-group">
                  <label className="form-label">Poll Interval (seconds)</label>
                  <input className="form-control" type="number" min="30" value={settings.poll_interval_seconds ?? ''} onChange={e => set('poll_interval_seconds', e.target.value)} />
                  <div className="form-hint">Minimum 30 seconds. Restart applies new interval.</div>
                </div>
              </div>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label">Alert Cooldown (minutes)</label>
                  <input className="form-control" type="number" min="1" value={settings.alert_cooldown_minutes ?? ''} onChange={e => set('alert_cooldown_minutes', e.target.value)} />
                  <div className="form-hint">Minimum time between repeat alerts for the same issue.</div>
                </div>
                <div className="form-group">
                  <label className="form-label">Alert Retention (days)</label>
                  <input className="form-control" type="number" min="0" value={settings.alert_retention_days ?? ''} onChange={e => set('alert_retention_days', e.target.value)} />
                  <div className="form-hint">Alerts older than this are auto-deleted each poll cycle. Set to 0 to keep forever.</div>
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button className="btn btn-primary" onClick={() => handleSave(['app_name','default_lag_threshold_minutes','default_snapshot_queue_threshold','poll_interval_seconds','alert_cooldown_minutes','alert_retention_days'])} disabled={saving}>
                  {saving ? 'Saving…' : 'Save General Settings'}
                </button>
              </div>
            </div>
          </div>
        )}

        {tab === 'smtp' && <SmtpTab settings={settings} set={set} onSave={handleSave} saving={saving} toast={toast} />}

        {tab === 'maintenance' && (
          <MaintenanceTab toast={toast} settings={settings} />
        )}

        {tab === 'alerts' && (
          <div className="card" style={{ maxWidth: 600 }}>
            <div className="card-header"><span className="card-title"><Bell size={14} /> Alert Recipients</span></div>
            <div className="card-body">
              <div className="form-group">
                <label className="form-label">Email Recipients</label>
                <textarea
                  className="form-control form-control-mono"
                  rows={4}
                  value={settings.alert_recipients || ''}
                  onChange={e => set('alert_recipients', e.target.value)}
                  placeholder="ops@example.com, alerts@example.com"
                />
                <div className="form-hint">Comma-separated list of addresses to receive all alerts.</div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <TestAlertButton toast={toast} />
                <button className="btn btn-primary" onClick={() => handleSave(['alert_recipients'])} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Recipients'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function SmtpTab({ settings, set, onSave, saving, toast }) {
  const [testing, setTesting] = useState(false);
  const [testRecipient, setTestRecipient] = useState('');
  const [testResult, setTestResult] = useState(null);

  const smtpKeys = ['smtp_host','smtp_port','smtp_secure','smtp_user','smtp_pass','smtp_from'];

  const handleTest = async () => {
    if (!testRecipient) { toast('Enter a test recipient', 'error'); return; }
    setTesting(true); setTestResult(null);
    try {
      const payload = {
        smtp_host: settings.smtp_host,
        smtp_port: settings.smtp_port,
        smtp_secure: settings.smtp_secure,
        smtp_user: settings.smtp_user,
        smtp_pass: settings.smtp_pass || undefined,
        smtp_from: settings.smtp_from,
        test_recipient: testRecipient,
      };
      const result = await api.testSmtp(payload);
      setTestResult(result);
      toast(result.success ? 'Test email sent!' : result.error, result.success ? 'success' : 'error');
    } catch (e) { toast(e.message, 'error'); setTestResult({ success: false, error: e.message }); }
    setTesting(false);
  };

  return (
    <div className="card" style={{ maxWidth: 600 }}>
      <div className="card-header"><span className="card-title"><Mail size={14} /> SMTP Configuration</span></div>
      <div className="card-body">
        <div className="form-row form-row-2">
          <div className="form-group">
            <label className="form-label">SMTP Host</label>
            <input className="form-control form-control-mono" value={settings.smtp_host || ''} onChange={e => set('smtp_host', e.target.value)} placeholder="smtp.example.com" />
          </div>
          <div className="form-group">
            <label className="form-label">Port</label>
            <input className="form-control form-control-mono" type="number" value={settings.smtp_port || 587} onChange={e => set('smtp_port', e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <div className="toggle-wrap">
            <label className="toggle">
              <input type="checkbox" checked={settings.smtp_secure === 'true'} onChange={e => set('smtp_secure', String(e.target.checked))} />
              <span className="toggle-slider" />
            </label>
            <span style={{ fontSize: 13, color: 'var(--text-1)' }}>Use TLS/SSL (port 465)</span>
          </div>
          <div className="form-hint">Disable for STARTTLS (port 587) or plain SMTP.</div>
        </div>
        <div className="section-divider" />
        <div className="form-row form-row-2">
          <div className="form-group">
            <label className="form-label">Username</label>
            <input className="form-control" value={settings.smtp_user || ''} onChange={e => set('smtp_user', e.target.value)} placeholder="alerts@example.com" />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input className="form-control" type="password" value={settings.smtp_pass || ''} onChange={e => set('smtp_pass', e.target.value)} placeholder="••••••••" />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">From Address</label>
          <input className="form-control" value={settings.smtp_from || ''} onChange={e => set('smtp_from', e.target.value)} placeholder="Qumulo Monitor <alerts@example.com>" />
        </div>

        <div className="section-divider" />
        <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 12 }}>Send a test email to verify your SMTP config:</p>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <input className="form-control" style={{ flex: 1 }} type="email" value={testRecipient} onChange={e => setTestRecipient(e.target.value)} placeholder="you@example.com" />
          <button className="btn btn-secondary" onClick={handleTest} disabled={testing}>
            {testing ? <Spinner /> : <Send size={13} />} {testing ? 'Sending…' : 'Send Test'}
          </button>
        </div>
        {testResult && (
          <div className={testResult.success ? 'inline-success' : 'inline-error'}>
            {testResult.success ? '✓ Test email sent successfully' : `✗ ${testResult.error}`}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-primary" onClick={() => onSave(smtpKeys)} disabled={saving}>
            {saving ? 'Saving…' : 'Save SMTP Settings'}
          </button>
        </div>
      </div>
    </div>
  );
}

function TestAlertButton({ toast }) {
  const [sending, setSending] = useState(false);
  const handle = async () => {
    setSending(true);
    try {
      const r = await api.sendTestAlert();
      toast(r.sent ? 'Test alert sent!' : 'SMTP not configured', r.sent ? 'success' : 'error');
    } catch (e) { toast(e.message, 'error'); }
    setSending(false);
  };
  return (
    <button className="btn btn-secondary btn-sm" onClick={handle} disabled={sending}>
      <Bell size={13} /> {sending ? 'Sending…' : 'Send Test Alert'}
    </button>
  );
}

function MaintenanceTab({ toast, settings }) {
  const [purging, setPurging] = useState(false);
  const [customDays, setCustomDays] = useState('');
  const [confirmAll, setConfirmAll] = useState(false);

  const retentionDays = parseInt(settings.alert_retention_days) || 90;

  const handlePurge = async (days) => {
    setPurging(true);
    try {
      const result = await api.purgeAlerts(days);
      toast(`Deleted ${result.deleted} alert${result.deleted !== 1 ? 's' : ''} older than ${days} days`, 'success');
    } catch (e) { toast(e.message, 'error'); }
    setPurging(false);
  };

  const handlePurgeAll = async () => {
    setPurging(true);
    try {
      const result = await api.purgeAllAlerts();
      toast(`Deleted all ${result.deleted} alert${result.deleted !== 1 ? 's' : ''}`, 'success');
    } catch (e) { toast(e.message, 'error'); }
    setConfirmAll(false);
    setPurging(false);
  };

  return (
    <div className="card" style={{ maxWidth: 600 }}>
      <div className="card-header"><span className="card-title">Alert Log Cleanup</span></div>
      <div className="card-body">
        <p style={{ fontSize: 13, color: 'var(--text-1)', marginBottom: 20, lineHeight: 1.6 }}>
          Manually remove alert log entries regardless of the automatic retention policy.
          Automatic cleanup runs every poll cycle and removes alerts older than <strong style={{ color: 'var(--lychee-100)' }}>{retentionDays} days</strong> (set in General settings).
          The buttons below are one-time operations and do not change that setting.
        </p>

        <div className="section-divider" />

        <div style={{ marginBottom: 20 }}>
          <div className="form-label" style={{ marginBottom: 10 }}>Purge by age</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[7, 30, 90].map(d => (
              <button key={d} className="btn btn-secondary btn-sm" disabled={purging} onClick={() => handlePurge(d)}>
                Delete older than {d} days
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
            <input
              className="form-control"
              type="number"
              min="1"
              style={{ maxWidth: 100 }}
              placeholder="Days"
              value={customDays}
              onChange={e => setCustomDays(e.target.value)}
            />
            <button
              className="btn btn-secondary btn-sm"
              disabled={purging || !customDays}
              onClick={() => handlePurge(parseInt(customDays))}
            >
              Delete older than {customDays || '…'} days
            </button>
          </div>
        </div>

        <div className="section-divider" />

        <div>
          <div className="form-label" style={{ marginBottom: 6 }}>Purge all alerts</div>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }}>
            Permanently deletes the entire alert log. This cannot be undone.
          </p>
          {!confirmAll ? (
            <button className="btn btn-danger btn-sm" onClick={() => setConfirmAll(true)}>
              Delete All Alerts…
            </button>
          ) : (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 13, color: 'var(--red)' }}>Are you sure? This cannot be undone.</span>
              <button className="btn btn-danger btn-sm" disabled={purging} onClick={handlePurgeAll}>
                {purging ? 'Deleting…' : 'Yes, Delete All'}
              </button>
              <button className="btn btn-secondary btn-sm" onClick={() => setConfirmAll(false)}>Cancel</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
