import { useState, useEffect, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { GitCompare, ArrowLeft, Edit2, Trash2, ToggleLeft, ToggleRight, Clock, RefreshCw, ChevronRight } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/useToast';
import { StatusBadge, LagDisplay, SnapshotQueueDisplay, JobProgressDisplay, RelativeTime, Spinner, EmptyState, Modal, ConfirmModal, formatDate } from '../components/shared';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';

// ─── List Page ──────────────────────────────────────────────────────────────

export function RelationshipsPage() {
  const { isAdmin } = useAuth();
  const [rels, setRels] = useState([]);
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [editRel, setEditRel] = useState(null);
  const [deleteRel, setDeleteRel] = useState(null);
  const { toast } = useToast();

  const load = useCallback(async () => {
    const [r, s] = await Promise.all([api.relationships(), api.settings()]);
    setRels(r); setSettings(s); setLoading(false);
  }, []);
  useEffect(() => { load(); }, [load]);

  const threshold = parseInt(settings.default_lag_threshold_minutes) || 60;

  const filtered = rels.filter(r =>
    !search || [r.display_name, r.qumulo_id, r.cluster_name, r.source_path, r.target_host]
      .some(v => v?.toLowerCase().includes(search.toLowerCase()))
  );

  const handleDelete = async () => {
    await api.deleteRelationship(deleteRel.id);
    toast('Relationship deleted', 'success');
    setDeleteRel(null); load();
  };

  const handleToggle = async (rel) => {
    await api.updateRelationship(rel.id, { enabled: !rel.enabled });
    toast(`Relationship ${rel.enabled ? 'disabled' : 'enabled'}`, 'success');
    load();
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Replication Relationships</div>
          <div className="page-subtitle">{rels.length} total relationships across all clusters</div>
        </div>
      </div>
      <div className="page-body">
        <div className="filter-bar" style={{ marginBottom: 16 }}>
          <div className="search-input-wrap">
            <GitCompare size={14} />
            <input className="form-control search-input" placeholder="Search relationships…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
        </div>

        <div className="card">
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner /></div>
          ) : filtered.length === 0 ? (
            <EmptyState icon={<GitCompare size={40} />} title="No relationships" body="Add clusters and discover/import replication relationships." />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Cluster</th>
                  <th>Direction</th>
                  <th>Status</th>
                  <th>Lag / Queued</th>
                  <th>Threshold / Max</th>
                  <th>Last Poll</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(rel => {
                  const lagThresh = rel.lag_threshold_minutes ?? threshold;
                  const isSnapshot = rel.replication_mode === 'REPLICATION_SNAPSHOT_POLICY';
                  const clusterDisabled = rel.replication_enabled == 0 && rel.replication_enabled !== null;
                  // For continuous rels, check lag even if disabled — old recovery_point matters
                  const lagExceedsThreshold = !isSnapshot && rel.latest_lag_seconds > lagThresh * 60;
                  const status = rel.end_reason ? 'ended'
                    : rel.latest_status === 'error' ? 'error'
                    : !rel.latest_status ? 'unknown'
                    : (rel.latest_status === 'disabled' || clusterDisabled) ? 'disabled'
                    : rel.latest_status === 'running' ? 'running'
                    : lagExceedsThreshold ? 'warning'
                    : 'ok';
                  return (
                    <tr key={rel.id} style={{ opacity: rel.enabled ? 1 : 0.5 }}>
                      <td>
                        <Link to={`/relationships/${rel.id}`} style={{ color: 'var(--text-0)', fontWeight: 500 }}>
                          {rel.display_name || rel.qumulo_id}
                        </Link>
                      </td>
                      <td className="text-muted">{rel.cluster_name}</td>
                      <td><span className={`badge ${rel.direction === 'source' ? 'badge-running' : 'badge-viewer'}`}>{rel.direction}</span></td>
                      <td>
                        {!rel.enabled
                          ? <span className="badge badge-unknown">monitoring off</span>
                          : <StatusBadge status={status} />
                        }
                      </td>
                      <td>
                        {isSnapshot
                          ? <span className="mono text-sm" style={{ color: rel.replication_enabled == 0 ? 'var(--text-3)' : 'var(--text-1)' }}>
                              {rel.replication_enabled == 0 ? 0 : (rel.latest_lag_seconds ?? '—')}
                            </span>
                          : <LagDisplay lagSeconds={rel.latest_lag_seconds} thresholdMinutes={lagThresh} />
                        }
                      </td>
                      <td className="mono text-sm text-muted">
                        {isSnapshot
                          ? `${(rel.snapshot_queue_threshold ?? parseInt(settings.default_snapshot_queue_threshold) ?? 3)} max`
                          : `${lagThresh}m`
                        }
                      </td>
                      <td className="text-muted text-sm"><RelativeTime ts={rel.last_polled_at} /></td>
                      <td>
                        <div style={{ display: 'flex', gap: 4 }}>
                          <Link to={`/relationships/${rel.id}`} className="btn btn-ghost btn-icon btn-sm" title="View detail">
                            <ChevronRight size={14} />
                          </Link>
                          {isAdmin && <>
                            <button className="btn btn-ghost btn-icon btn-sm" title={rel.enabled ? 'Disable' : 'Enable'} onClick={() => handleToggle(rel)}>
                              {rel.enabled ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
                            </button>
                            <button className="btn btn-ghost btn-icon btn-sm" title="Edit" onClick={() => setEditRel(rel)}>
                              <Edit2 size={14} />
                            </button>
                            <button className="btn btn-ghost btn-icon btn-sm" title="Delete" onClick={() => setDeleteRel(rel)}>
                              <Trash2 size={14} />
                            </button>
                          </>}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {editRel && <EditRelModal rel={editRel} onClose={() => setEditRel(null)} onSaved={() => { setEditRel(null); load(); }} />}
      {deleteRel && (
        <ConfirmModal
          title="Delete Relationship"
          message={`Delete "${deleteRel.display_name || deleteRel.qumulo_id}"? This will remove all poll history and alert logs.`}
          onConfirm={handleDelete}
          onClose={() => setDeleteRel(null)}
        />
      )}
    </>
  );
}

// ─── Edit Modal ──────────────────────────────────────────────────────────────

function EditRelModal({ rel, onClose, onSaved }) {
  const { toast } = useToast();
  const isSnapshot = rel.replication_mode === 'REPLICATION_SNAPSHOT_POLICY';
  const [form, setForm] = useState({
    display_name: rel.display_name || '',
    lag_threshold_minutes: rel.lag_threshold_minutes ?? '',
    snapshot_queue_threshold: rel.snapshot_queue_threshold ?? '',
    source_path: rel.source_path || '',
    target_host: rel.target_host || '',
    target_path: rel.target_path || '',
    alert_recipients: rel.alert_recipients || '',
  });
  const [saving, setSaving] = useState(false);
  const [groups, setGroups] = useState([]);

  useEffect(() => {
    api.recipientGroups().then(setGroups).catch(() => {});
  }, []);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateRelationship(rel.id, {
        ...form,
        lag_threshold_minutes: form.lag_threshold_minutes === '' ? null : parseInt(form.lag_threshold_minutes),
        snapshot_queue_threshold: form.snapshot_queue_threshold === '' ? null : parseInt(form.snapshot_queue_threshold),
        alert_recipients: form.alert_recipients.trim() || null,
      });
      toast('Saved', 'success'); onSaved();
    } catch (e) { toast(e.message, 'error'); }
    setSaving(false);
  };

  return (
    <Modal title="Edit Relationship" onClose={onClose} footer={
      <><button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button></>
    }>
      <div className="form-group">
        <label className="form-label">Display Name</label>
        <input className="form-control" value={form.display_name} onChange={e => set('display_name', e.target.value)} />
      </div>
      {isSnapshot ? (
        <div className="form-group">
          <label className="form-label">Snapshot Queue Threshold</label>
          <input className="form-control" type="number" min="1" value={form.snapshot_queue_threshold} onChange={e => set('snapshot_queue_threshold', e.target.value)} placeholder="Use default (3)" />
          <div className="form-hint">Alert when queued snapshot count exceeds this. Leave blank to use the system default.</div>
        </div>
      ) : (
        <div className="form-group">
          <label className="form-label">Lag Threshold (minutes)</label>
          <input className="form-control" type="number" min="1" value={form.lag_threshold_minutes} onChange={e => set('lag_threshold_minutes', e.target.value)} placeholder="Use default" />
          <div className="form-hint">Alert when replication lags beyond this. Leave blank to use the system default.</div>
        </div>
      )}
      <div className="form-row form-row-2">
        <div className="form-group">
          <label className="form-label">Source Path</label>
          <input className="form-control form-control-mono" value={form.source_path} readOnly disabled style={{ opacity: 0.6, cursor: 'not-allowed' }} />
          <div className="form-hint">Set by Qumulo — not editable.</div>
        </div>
        <div className="form-group">
          <label className="form-label">Target Host</label>
          <input className="form-control form-control-mono" value={form.target_host} readOnly disabled style={{ opacity: 0.6, cursor: 'not-allowed' }} />
          <div className="form-hint">Set by Qumulo — not editable.</div>
        </div>
      </div>
      <div className="form-group">
        <label className="form-label">Alert Recipients (optional)</label>
        <input
          className="form-control"
          value={form.alert_recipients}
          onChange={e => set('alert_recipients', e.target.value)}
          placeholder="Leave blank to use default recipients"
        />
        <div className="form-hint">
          Comma-separated emails or group names, added alongside the default recipients.
          {groups.length > 0 && (
            <span> Available groups: {groups.map((g, i) => (
              <span key={g.id}>
                <span
                  style={{ color: 'var(--agave-500)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                  onClick={() => {
                    const current = form.alert_recipients.trim();
                    set('alert_recipients', current ? current + ', ' + g.name : g.name);
                  }}
                  title={g.description || g.addresses}
                >{g.name}</span>{i < groups.length - 1 ? ', ' : ''}
              </span>
            ))}</span>
          )}
        </div>
      </div>
    </Modal>
  );
}

// ─── Detail Page ──────────────────────────────────────────────────────────────

export function RelationshipDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { isAdmin } = useAuth();
  const { toast } = useToast();
  const [data, setData] = useState(null);
  const [settings, setSettings] = useState({});
  const [jobStats, setJobStats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [editOpen, setEditOpen] = useState(false);

  const load = useCallback(async () => {
    const [d, s, js] = await Promise.all([api.relationship(id), api.settings(), api.jobStats(id)]);
    setData(d); setSettings(s); setJobStats(js); setLoading(false);
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>;
  if (!data) return <div className="page-body">Relationship not found.</div>;

  const threshold = data.lag_threshold_minutes ?? parseInt(settings.default_lag_threshold_minutes) ?? 60;
  const latest = data.history?.[0];
  let activeJobStatus = null;
  if (latest?.status === 'running') {
    try { activeJobStatus = JSON.parse(latest.raw_data || '{}').replication_job_status || null; } catch {}
  }
  const status = latest?.status === 'error' ? 'error' : !latest ? 'unknown' :
    (latest.lag_seconds > threshold * 60 ? 'warning' : latest.status);

  const chartData = [...(data.history || [])].reverse().slice(-50).map(h => ({
    t: new Date(h.polled_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
    lag: h.lag_seconds ? Math.round(h.lag_seconds / 60) : null,
  }));

  const handleAck = async (alertId) => {
    await api.acknowledgeAlert(id, alertId);
    toast('Alert acknowledged', 'success');
    load();
  };

  const handleAckAll = async () => {
    const result = await api.acknowledgeAllRelAlerts(id);
    toast(`${result.acknowledged} alert${result.acknowledged !== 1 ? 's' : ''} acknowledged`, 'success');
    load();
  };

  return (
    <>
      <div className="page-header">
        <div>
          <button className="btn btn-ghost btn-sm" style={{ marginBottom: 8 }} onClick={() => navigate(-1)}>
            <ArrowLeft size={13} /> Back
          </button>
          <div className="page-title">{data.display_name || data.qumulo_id}</div>
          <div className="page-subtitle">{data.cluster_name} · {data.direction} relationship</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <StatusBadge status={status} />
          {isAdmin && <button className="btn btn-secondary btn-sm" onClick={() => setEditOpen(true)}><Edit2 size={13} /> Edit</button>}
          <button className="btn btn-secondary btn-sm" onClick={load}><RefreshCw size={13} /></button>
        </div>
      </div>

      <div className="page-body">
        <div className="tabs">
          {['overview', 'history', 'job-stats', 'alerts'].map(t => (
            <button key={t} className={`tab-btn ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
              {t === 'job-stats' ? 'Job Stats' : t.charAt(0).toUpperCase() + t.slice(1)}
              {t === 'alerts' && data.alerts?.filter(a => !a.acknowledged).length > 0 &&
                <span style={{ marginLeft: 6, background: 'var(--red)', color: '#fff', borderRadius: 10, padding: '0 5px', fontSize: 10 }}>
                  {data.alerts.filter(a => !a.acknowledged).length}
                </span>}
            </button>
          ))}
        </div>

        {tab === 'overview' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card">
              <div className="card-header"><span className="card-title">Configuration</span></div>
              <div className="card-body">
                {[
                  ['Qumulo ID', data.qumulo_id, true],
                  ['Cluster', `${data.cluster_name} (${data.cluster_host})`],
                  ['Direction', data.direction],
                  ['Source Path', data.source_path, true],
                  ['Target Host', data.target_host, true],
                  ['Target Path', data.target_path, true],
                  ['Lag Threshold', `${threshold} minutes${data.lag_threshold_minutes ? ' (custom)' : ' (default)'}`],
                  ['Monitoring', data.enabled ? 'Enabled' : 'Disabled'],
                  ['Cluster Replication', data.end_reason
                    ? <span className="badge badge-error">Ended</span>
                    : data.replication_enabled === 0
                    ? <span className="badge badge-warning">Disabled on cluster</span>
                    : data.replication_enabled === 1
                    ? <span className="badge badge-ok">Enabled on cluster</span>
                    : <span className="text-muted text-sm">Unknown</span>],
                ].map(([label, val, mono]) => val && (
                  <div key={label} style={{ display: 'flex', gap: 12, marginBottom: 10, fontSize: 13 }}>
                    <span style={{ color: 'var(--text-2)', minWidth: 110 }}>{label}</span>
                    <span style={{ color: 'var(--text-0)', fontFamily: mono ? 'var(--font-mono)' : undefined, fontSize: mono ? 12 : 13 }}>{val}</span>
                  </div>
                ))}
              </div>
            </div>

            {data.end_reason && (
              <div className="card" style={{ gridColumn: '1 / -1', borderColor: 'var(--pomegranate-600)', background: 'var(--pomegranate-700)' }}>
                <div className="card-header" style={{ borderColor: 'var(--pomegranate-600)' }}>
                  <span className="card-title" style={{ color: 'var(--pomegranate-400)' }}>
                    <span className="badge badge-error" style={{ marginRight: 8 }}>ENDED</span>
                    This relationship has been ended on the cluster
                  </span>
                </div>
                <div className="card-body" style={{ color: 'var(--pomegranate-400)', fontSize: 13, lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {data.end_reason}
                </div>
              </div>
            )}

            {activeJobStatus && (
              <div className="card" style={{ gridColumn: '1 / -1', borderColor: 'var(--agave-700)' }}>
                <div className="card-header" style={{ borderColor: 'var(--agave-700)' }}>
                  <span className="card-title" style={{ color: 'var(--agave-400)' }}>
                    <span className="status-dot running" style={{ marginRight: 6 }} />
                    Active Transfer in Progress
                  </span>
                  <span className="text-muted text-sm">as of last poll</span>
                </div>
                <div className="card-body">
                  <JobProgressDisplay jobStatus={activeJobStatus} />
                </div>
              </div>
            )}

            <div className="card">
              <div className="card-header"><span className="card-title">Latest Status</span></div>
              <div className="card-body">
                {latest ? <>
                  {[
                    ['Status', <StatusBadge status={status} />],
                    ['Lag / Queue', (data.replication_mode || '').includes('SNAPSHOT')
                      ? <SnapshotQueueDisplay queueCount={latest.lag_seconds} threshold={(data.snapshot_queue_threshold ?? parseInt(settings.default_snapshot_queue_threshold) ?? 3)} />
                      : <LagDisplay lagSeconds={latest.lag_seconds} thresholdMinutes={threshold} />],
                    ['Last Polled', formatDate(latest.polled_at)],
                    ['Error', latest.error_message && <span style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{latest.error_message}</span>],
                  ].map(([label, val]) => val && (
                    <div key={label} style={{ display: 'flex', gap: 12, marginBottom: 10, fontSize: 13, alignItems: 'center' }}>
                      <span style={{ color: 'var(--text-2)', minWidth: 110 }}>{label}</span>
                      {val}
                    </div>
                  ))}
                </> : <p className="text-muted text-sm">Not yet polled.</p>}
              </div>
            </div>

            <div className="card" style={{ gridColumn: '1 / -1', padding: '12px 18px', background: 'var(--blackberry-850)', border: '1px solid var(--blackberry-700)', borderRadius: 'var(--radius)' }}>
              <span style={{ fontSize: 12, color: 'var(--lychee-500)' }}>Lag trend and job throughput charts have moved to the <strong style={{ color: 'var(--agave-400)' }}>Job Stats</strong> tab.</span>
            </div>
          </div>
        )}

        {tab === 'history' && (
          <div className="card">
            <table className="data-table">
              <thead><tr><th>Time</th><th>Status</th><th>Lag / Progress</th><th>Error</th></tr></thead>
              <tbody>
                {(data.history || []).map((h, i) => {
                  let jobStatus = null;
                  if (h.status === 'running') {
                    try { jobStatus = JSON.parse(h.raw_data || '{}').replication_job_status || null; } catch {}
                  }
                  return (
                  <tr key={i}>
                    <td className="mono text-sm">{formatDate(h.polled_at)}</td>
                    <td><StatusBadge status={h.status} /></td>
                    <td>
                      {jobStatus
                        ? <JobProgressDisplay jobStatus={jobStatus} compact />
                        : <LagDisplay lagSeconds={h.lag_seconds} thresholdMinutes={threshold} />
                      }
                    </td>
                    <td style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{h.error_message || '—'}</td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'job-stats' && (
          <JobStatsTab jobStats={jobStats} history={data.history || []} threshold={threshold} isSnapshot={data.replication_mode === 'REPLICATION_SNAPSHOT_POLICY'} data={data} />
        )}

        {tab === 'alerts' && (
          <div className="card">
            {(data.alerts || []).length === 0 ? (
              <EmptyState icon={<span style={{ fontSize: 32 }}>✓</span>} title="No alerts" body="No alerts have been triggered for this relationship." />
            ) : (
              <>
                {isAdmin && data.alerts.some(a => !a.acknowledged) && (
                  <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end' }}>
                    <button className="btn btn-secondary btn-sm" onClick={handleAckAll}>
                      Acknowledge All ({data.alerts.filter(a => !a.acknowledged).length})
                    </button>
                  </div>
                )}
              <table className="data-table">
                <thead><tr><th>Time</th><th>Type</th><th>Message</th><th>Ack</th></tr></thead>
                <tbody>
                  {data.alerts.map(a => (
                    <tr key={a.id} className={`alert-row-${a.alert_type}`}>
                      <td className="mono text-sm">{formatDate(a.sent_at)}</td>
                      <td><span className={`badge ${a.alert_type === 'error' ? 'badge-error' : a.alert_type === 'lag' ? 'badge-warning' : 'badge-ok'}`}>{a.alert_type}</span></td>
                      <td className="text-sm">{a.message}</td>
                      <td>
                        {a.acknowledged
                          ? <span className="text-muted text-sm">by {a.acknowledged_by}</span>
                          : isAdmin && <button className="btn btn-ghost btn-sm" onClick={() => handleAck(a.id)}>Ack</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </>
            )}
          </div>
        )}
      </div>

      {editOpen && <EditRelModal rel={data} onClose={() => setEditOpen(false)} onSaved={() => { setEditOpen(false); load(); }} />}
    </>
  );
}

// ─── Job Stats Tab ─────────────────────────────────────────────────────────────

function fmtBytes(n) {
  n = parseInt(n);
  if (isNaN(n) || n === 0) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 ** 2) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 ** 3) return (n / 1024 ** 2).toFixed(1) + ' MB';
  return (n / 1024 ** 3).toFixed(2) + ' GB';
}

function fmtThroughput(n) {
  n = parseInt(n);
  if (isNaN(n) || n === 0) return '0 B/s';
  if (n < 1024) return n + ' B/s';
  if (n < 1024 ** 2) return (n / 1024).toFixed(1) + ' KB/s';
  if (n < 1024 ** 3) return (n / 1024 ** 2).toFixed(1) + ' MB/s';
  return (n / 1024 ** 3).toFixed(2) + ' GB/s';
}

function JobStatsTab({ jobStats, history, threshold, isSnapshot, data }) {
  const hasStats = jobStats && jobStats.length > 0;
  const hasHistory = history && history.length > 0;

  if (!hasStats && !hasHistory) {
    return (
      <div className="card">
        <EmptyState
          icon={<span style={{ fontSize: 32 }}>📊</span>}
          title="No data yet"
          body="Lag history and job stats will appear here after polling begins."
        />
      </div>
    );
  }

  // Build a unified timeline from all poll timestamps + job stat timestamps
  // Key: ISO timestamp string → merged data point
  const pointMap = new Map();

  // Add lag from poll history (all polls)
  for (const h of [...history].reverse()) {
    const ts = h.polled_at;
    if (!pointMap.has(ts)) pointMap.set(ts, { ts, lag: null, bytes: null, files: null, throughput: null });
    const p = pointMap.get(ts);
    if (!isSnapshot && h.lag_seconds != null) {
      p.lag = Math.round(h.lag_seconds / 60);
    }
  }

  // Add job stats (only captured when running)
  for (const s of jobStats) {
    const ts = s.captured_at;
    if (!pointMap.has(ts)) pointMap.set(ts, { ts, lag: null, bytes: null, files: null, throughput: null });
    const p = pointMap.get(ts);
    p.bytes = Math.round(parseInt(s.bytes_transferred) / (1024 ** 2));
    p.files = parseInt(s.files_transferred);
    p.throughput = Math.round(parseInt(s.throughput_current) / 1024);
  }

  // Sort by time and format X label
  const merged = [...pointMap.values()]
    .sort((a, b) => a.ts < b.ts ? -1 : 1)
    .map(p => ({
      ...p,
      t: new Date(p.ts).toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
      }),
    }));

  const latest = hasStats ? jobStats[jobStats.length - 1] : null;

  const printPDF = () => {
    const charts = document.querySelectorAll('.recharts-wrapper');
    const relName = data?.display_name || data?.qumulo_id || 'relationship';
    const clusterName = data?.cluster_name || '';
    const now = new Date().toLocaleString();

    // Resolve CSS variables to actual computed values so they survive the new window
    const rootStyle = getComputedStyle(document.documentElement);
    const resolveColor = (val) => {
      if (!val) return val;
      return val.replace(/var\(([^)]+)\)/g, (_, v) => {
        const resolved = rootStyle.getPropertyValue(v.trim()).trim();
        return resolved || '#888';
      });
    };

    const resolveElement = (el) => {
      // Resolve stroke, fill, stop-color on all elements
      ['stroke', 'fill', 'stop-color', 'color'].forEach(attr => {
        const val = el.getAttribute(attr);
        if (val && val.includes('var(')) el.setAttribute(attr, resolveColor(val));
      });
      // Also resolve inline style stroke/fill
      if (el.style) {
        if (el.style.stroke && el.style.stroke.includes('var('))
          el.style.stroke = resolveColor(el.style.stroke);
        if (el.style.fill && el.style.fill.includes('var('))
          el.style.fill = resolveColor(el.style.fill);
        if (el.style.color && el.style.color.includes('var('))
          el.style.color = resolveColor(el.style.color);
      }
      for (const child of el.children) resolveElement(child);
    };

    const svgs = [...charts].map(c => {
      const svg = c.querySelector('svg');
      if (!svg) return '';
      const clone = svg.cloneNode(true);
      clone.setAttribute('width', svg.getBoundingClientRect().width);
      clone.setAttribute('height', svg.getBoundingClientRect().height);
      // Resolve all CSS variables in the clone before serializing
      resolveElement(clone);
      return clone.outerHTML;
    });

    const chartLabels = [
      ...(isSnapshot ? [] : ['Lag (minutes)']),
      ...(hasStats ? ['Data Moved (MB)', 'Throughput (KB/s)', 'Files Transferred'] : []),
    ];

    const win = window.open('', '_blank');
    win.document.write(`<!DOCTYPE html>
<html>
<head>
  <title>Replication Stats — ${relName}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; background: #fff; color: #111; padding: 32px; }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 4px; }
    .meta { font-size: 12px; color: #666; margin-bottom: 28px; }
    .chart-block { margin-bottom: 32px; page-break-inside: avoid; }
    .chart-label { font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #333; border-bottom: 1px solid #e0e0e0; padding-bottom: 6px; }
    svg { display: block; width: 100% !important; max-width: 100%; }
    .footer { font-size: 11px; color: #999; margin-top: 24px; text-align: right; }
    @media print {
      body { padding: 16px; }
      @page { margin: 16mm; }
    }
  </style>
</head>
<body>
  <h1>Replication Stats: ${relName}</h1>
  <div class="meta">${clusterName} &nbsp;·&nbsp; Exported ${now}</div>
  ${svgs.map((svg, i) => `
    <div class="chart-block">
      <div class="chart-label">${chartLabels[i] || 'Chart ' + (i + 1)}</div>
      ${svg}
    </div>
  `).join('')}
  <div class="footer">Generated by Qumulo Replication Monitor</div>
  <script>window.onload = () => { window.print(); }</script>
</body>
</html>`);
    win.document.close();
  };

  const exportCSV = () => {
    const rows = [
      ['Timestamp', 'Lag (minutes)', 'Data Moved (MB)', 'Files Transferred', 'Throughput (KB/s)', 'Avg Throughput (KB/s)'],
    ];
    for (const p of merged) {
      const s = jobStats.find(s => s.captured_at === p.ts);
      const avgThroughput = s ? Math.round(parseInt(s.throughput_overall) / 1024) : '';
      rows.push([p.ts, p.lag ?? '', p.bytes ?? '', p.files ?? '', p.throughput ?? '', avgThroughput]);
    }
    const csv = rows.map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'replication-stats-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const chartProps = { margin: { top: 4, right: 20, bottom: 0, left: 0 } };
  const tooltipStyle = {
    contentStyle: { background: 'var(--blackberry-850)', border: '1px solid var(--blackberry-700)', borderRadius: 4, fontSize: 12 },
    labelStyle: { color: 'var(--lychee-300)' },
  };
  // Shared X axis props — same ticks across all charts
  const xAxisProps = {
    dataKey: 't',
    tick: { fontSize: 9, fill: 'var(--lychee-500)' },
    tickLine: false,
    interval: 'preserveStartEnd',
  };
  const yAxisProps = {
    tick: { fontSize: 10, fill: 'var(--lychee-500)' },
    tickLine: false,
    axisLine: false,
    width: 48,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* Summary row — latest job stats */}
      {latest && (
        <div className="stats-grid">
          {[
            { label: 'Data Moved', value: fmtBytes(latest.bytes_transferred) },
            { label: 'Files Moved', value: parseInt(latest.files_transferred).toLocaleString() },
            { label: 'Current Throughput', value: fmtThroughput(latest.throughput_current) },
            { label: 'Avg Throughput', value: fmtThroughput(latest.throughput_overall) },
          ].map(({ label, value }) => (
            <div key={label} className="stat-card">
              <div className="stat-label">{label}</div>
              <div style={{ fontSize: 18, fontWeight: 600, color: 'var(--agave-400)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>{value}</div>
              <div className="stat-sub">last captured</div>
            </div>
          ))}
        </div>
      )}

      {/* Export buttons */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn btn-secondary btn-sm" onClick={printPDF}>
          ↓ Export PDF
        </button>
        <button className="btn btn-secondary btn-sm" onClick={exportCSV}>
          ↓ Export CSV
        </button>
      </div>

      {/* Lag chart — shown for non-snapshot relationships */}
      {!isSnapshot && (
        <div className="card">
          <div className="card-header"><span className="card-title">Lag (minutes)</span></div>
          <div className="card-body" style={{ padding: '18px 8px' }}>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={merged} {...chartProps}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--blackberry-700)" />
                <XAxis {...xAxisProps} />
                <YAxis {...yAxisProps} />
                <Tooltip {...tooltipStyle} formatter={v => v != null ? [`${v}m`, 'Lag'] : ['—', 'Lag']} />
                <Line type="monotone" dataKey="lag" stroke="var(--agave-400)" strokeWidth={2} dot={false} connectNulls />
                {threshold && (
                  <ReferenceLine y={threshold} stroke="var(--pomegranate-500)" strokeDasharray="4 4" label={{ value: `${threshold}m`, position: 'right', fill: 'var(--pomegranate-400)', fontSize: 10 }} />
                )}
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Data Moved chart */}
      {hasStats && (
        <div className="card">
          <div className="card-header"><span className="card-title">Data Moved (MB)</span></div>
          <div className="card-body" style={{ padding: '18px 8px' }}>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={merged} {...chartProps}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--blackberry-700)" />
                <XAxis {...xAxisProps} />
                <YAxis {...yAxisProps} />
                <Tooltip {...tooltipStyle} formatter={v => v != null ? [`${v} MB`, 'Data Moved'] : ['—', 'Data Moved']} />
                <Line type="monotone" dataKey="bytes" stroke="var(--mint-400)" strokeWidth={2} dot={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Throughput chart */}
      {hasStats && (
        <div className="card">
          <div className="card-header"><span className="card-title">Throughput (KB/s)</span></div>
          <div className="card-body" style={{ padding: '18px 8px' }}>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={merged} {...chartProps}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--blackberry-700)" />
                <XAxis {...xAxisProps} />
                <YAxis {...yAxisProps} />
                <Tooltip {...tooltipStyle} formatter={v => v != null ? [`${v} KB/s`, 'Throughput'] : ['—', 'Throughput']} />
                <Line type="monotone" dataKey="throughput" stroke="var(--agave-500)" strokeWidth={2} dot={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Files chart */}
      {hasStats && (
        <div className="card">
          <div className="card-header"><span className="card-title">Files Transferred</span></div>
          <div className="card-body" style={{ padding: '18px 8px' }}>
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={merged} {...chartProps}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--blackberry-700)" />
                <XAxis {...xAxisProps} />
                <YAxis {...yAxisProps} />
                <Tooltip {...tooltipStyle} formatter={v => v != null ? [v?.toLocaleString(), 'Files'] : ['—', 'Files']} />
                <Line type="monotone" dataKey="files" stroke="var(--eggplant-400)" strokeWidth={2} dot={false} connectNulls={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {!hasStats && (
        <div className="card" style={{ padding: '20px 18px', border: '1px dashed var(--blackberry-600)' }}>
          <p style={{ fontSize: 13, color: 'var(--lychee-500)', textAlign: 'center' }}>
            Throughput charts appear when a replication job is caught running during a poll.
          </p>
        </div>
      )}

    </div>
  );
}
