import { useState, useEffect, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { GitCompare, ArrowLeft, Edit2, Trash2, ToggleLeft, ToggleRight, Clock, RefreshCw, ChevronRight } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/useToast';
import { StatusBadge, LagDisplay, SnapshotQueueDisplay, RelativeTime, Spinner, EmptyState, Modal, ConfirmModal, formatDate } from '../components/shared';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

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
                  const isSnapshot = (rel.replication_mode || '').includes('SNAPSHOT');
                  const clusterDisabled = rel.replication_enabled == 0 && rel.replication_enabled !== null;
                  // For continuous rels, check lag even if disabled — old recovery_point matters
                  const lagExceedsThreshold = !isSnapshot && rel.latest_lag_seconds > lagThresh * 60;
                  const status = rel.end_reason ? 'ended'
                    : rel.latest_status === 'error' ? 'error'
                    : !rel.latest_status ? 'unknown'
                    : (rel.latest_status === 'disabled' || clusterDisabled) ? 'disabled'
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
  const [form, setForm] = useState({
    display_name: rel.display_name || '',
    lag_threshold_minutes: rel.lag_threshold_minutes ?? '',
    source_path: rel.source_path || '',
    target_host: rel.target_host || '',
    target_path: rel.target_path || '',
  });
  const [saving, setSaving] = useState(false);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.updateRelationship(rel.id, {
        ...form,
        lag_threshold_minutes: form.lag_threshold_minutes === '' ? null : parseInt(form.lag_threshold_minutes),
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
      <div className="form-group">
        <label className="form-label">Lag Threshold (minutes)</label>
        <input className="form-control" type="number" min="1" value={form.lag_threshold_minutes} onChange={e => set('lag_threshold_minutes', e.target.value)} placeholder="Use default" />
        <div className="form-hint">Leave blank to use the system default threshold.</div>
      </div>
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
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [editOpen, setEditOpen] = useState(false);

  const load = useCallback(async () => {
    const [d, s] = await Promise.all([api.relationship(id), api.settings()]);
    setData(d); setSettings(s); setLoading(false);
  }, [id]);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><Spinner /></div>;
  if (!data) return <div className="page-body">Relationship not found.</div>;

  const threshold = data.lag_threshold_minutes ?? parseInt(settings.default_lag_threshold_minutes) ?? 60;
  const latest = data.history?.[0];
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
          {['overview', 'history', 'alerts'].map(t => (
            <button key={t} className={`tab-btn ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
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

            {chartData.length > 1 && (
              <div className="card" style={{ gridColumn: '1 / -1' }}>
                <div className="card-header"><span className="card-title">Lag Trend (minutes)</span></div>
                <div className="card-body" style={{ padding: '18px 8px' }}>
                  <ResponsiveContainer width="100%" height={160}>
                    <LineChart data={chartData} margin={{ top: 0, right: 20, bottom: 0, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                      <XAxis dataKey="t" tick={{ fontSize: 10, fill: 'var(--text-2)' }} tickLine={false} />
                      <YAxis tick={{ fontSize: 10, fill: 'var(--text-2)' }} tickLine={false} axisLine={false} />
                      <Tooltip
                        contentStyle={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 12 }}
                        labelStyle={{ color: 'var(--text-1)' }}
                        itemStyle={{ color: 'var(--accent)' }}
                      />
                      <Line type="monotone" dataKey="lag" stroke="var(--accent)" strokeWidth={2} dot={false} connectNulls />
                      {threshold && <Line type="monotone" dataKey={() => threshold} stroke="var(--red)" strokeWidth={1} strokeDasharray="4 4" dot={false} name="Threshold" />}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'history' && (
          <div className="card">
            <table className="data-table">
              <thead><tr><th>Time</th><th>Status</th><th>Lag</th><th>Error</th></tr></thead>
              <tbody>
                {(data.history || []).map((h, i) => (
                  <tr key={i}>
                    <td className="mono text-sm">{formatDate(h.polled_at)}</td>
                    <td><StatusBadge status={h.status} /></td>
                    <td><LagDisplay lagSeconds={h.lag_seconds} thresholdMinutes={threshold} /></td>
                    <td style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>{h.error_message || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'alerts' && (
          <div className="card">
            {(data.alerts || []).length === 0 ? (
              <EmptyState icon={<span style={{ fontSize: 32 }}>✓</span>} title="No alerts" body="No alerts have been triggered for this relationship." />
            ) : (
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
            )}
          </div>
        )}
      </div>

      {editOpen && <EditRelModal rel={data} onClose={() => setEditOpen(false)} onSaved={() => { setEditOpen(false); load(); }} />}
    </>
  );
}
