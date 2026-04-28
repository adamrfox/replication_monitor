import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, AlertTriangle, CheckCircle, Clock, Activity, ArrowRight } from 'lucide-react';
import { api } from '../api/client';
import { StatusBadge, LagDisplay, SnapshotQueueDisplay, JobProgressDisplay, RelativeTime, Spinner, EmptyState, deriveStatus } from '../components/shared';

export default function DashboardPage() {
  const [rels, setRels] = useState([]);
  const [settings, setSettings] = useState({});
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [filter, setFilter] = useState('all');

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([api.relationships(), api.settings()]);
      setRels(r); setSettings(s); setLastRefresh(new Date());
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); const iv = setInterval(load, 30000); return () => clearInterval(iv); }, [load]);

  const threshold = parseInt(settings.default_lag_threshold_minutes) || 60;
  const augmented = rels.map(r => {
    let latest_raw_job_status = null;
    if (r.latest_status === 'running' && r.latest_raw_data) {
      try {
        const raw = JSON.parse(r.latest_raw_data);
        latest_raw_job_status = raw.replication_job_status || null;
      } catch {}
    }
    return { ...r, default_threshold: threshold, latest_raw_job_status };
  });

  const counts = augmented.reduce((acc, r) => {
    const s = deriveStatus(r, threshold, parseInt(settings.default_snapshot_queue_threshold) || 3);
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  const visible = filter === 'all' ? augmented : augmented.filter(r => deriveStatus(r, threshold, parseInt(settings.default_snapshot_queue_threshold) || 3) === filter);

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">
            {rels.length} relationship{rels.length !== 1 ? 's' : ''} monitored
            {lastRefresh && <> · refreshed <RelativeTime ts={lastRefresh} /></>}
          </div>
        </div>
        <button className="btn btn-secondary btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      <div className="page-body">
        {/* Stats */}
        <div className="stats-grid" style={{ marginBottom: 20 }}>
          <div className="stat-card" style={{ cursor: 'pointer' }} onClick={() => setFilter('all')}>
            <div className="stat-label">Total Relationships</div>
            <div className="stat-value">{rels.length}</div>
            <div className="stat-sub" style={{ color: filter === 'all' ? 'var(--agave-500)' : undefined }}>
              {filter === 'all' ? '▶ showing all' : 'click to show all'}
            </div>
          </div>
          <div className="stat-card" style={{ cursor: 'pointer', outline: filter === 'ok' ? '1px solid var(--kiwi-500)' : undefined }} onClick={() => setFilter(filter === 'ok' ? 'all' : 'ok')}>
            <div className="stat-label">OK — Established</div>
            <div className="stat-value ok">{counts.ok || 0}</div>
            <div className="stat-sub" style={{ color: filter === 'ok' ? 'var(--kiwi-400)' : undefined }}>
              {filter === 'ok' ? '▶ filtered' : 'enabled, established, within threshold'}
            </div>
          </div>
          <div className="stat-card" style={{ cursor: 'pointer', outline: filter === 'warning' ? '1px solid var(--banana-400)' : undefined }} onClick={() => setFilter(filter === 'warning' ? 'all' : 'warning')}>
            <div className="stat-label">Lagging — Behind Threshold</div>
            <div className="stat-value warning">{counts.warning || 0}</div>
            <div className="stat-sub" style={{ color: filter === 'warning' ? 'var(--banana-400)' : undefined }}>
              {filter === 'warning' ? '▶ filtered' : 'idle but recovery point is too old'}
            </div>
          </div>
          <div className="stat-card" style={{ cursor: 'pointer', outline: filter === 'error' ? '1px solid var(--pomegranate-500)' : undefined }} onClick={() => setFilter(filter === 'error' ? 'all' : 'error')}>
            <div className="stat-label">Error — Job Failed</div>
            <div className="stat-value error">{counts.error || 0}</div>
            <div className="stat-sub" style={{ color: filter === 'error' ? 'var(--pomegranate-400)' : undefined }}>
              {filter === 'error' ? '▶ filtered' : 'cannot reach target or job faulted'}
            </div>
          </div>
        </div>

        {/* Filter pills */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
          {[
            { key: 'all',     label: 'All',      desc: null },
            { key: 'ok',      label: 'OK',        desc: 'Idle and caught up' },
            { key: 'running', label: 'Running',   desc: 'Actively transferring data' },
            { key: 'warning', label: 'Lagging',   desc: 'Idle but behind the lag threshold' },
            { key: 'error',   label: 'Error',     desc: 'Job failed or cannot reach target' },
            { key: 'disabled', label: 'Disabled', desc: 'Replication disabled on the cluster' },
            { key: 'unknown',  label: 'Unknown',  desc: 'Not yet polled or state unrecognized' },
            { key: 'ended',   label: 'Ended',     desc: 'Relationship has been permanently ended on the cluster' },
          ].map(({ key, label, desc }) => (
            <button
              key={key}
              className={`btn btn-sm ${filter === key ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setFilter(key)}
              title={desc || ''}
            >
              {label}
              {key !== 'all' && counts[key] ? ` (${counts[key]})` : ''}
            </button>
          ))}
        </div>

        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner /></div>
        ) : visible.length === 0 ? (
          <EmptyState
            icon={<Activity size={40} />}
            title="No relationships found"
            body="Add clusters and configure replication relationships to start monitoring."
            action={<Link to="/clusters" className="btn btn-primary btn-sm">Add Cluster</Link>}
          />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
            {visible.map(rel => {
              const status = deriveStatus(rel, threshold, parseInt(settings.default_snapshot_queue_threshold) || 3);
              return (
                <Link to={`/relationships/${rel.id}`} key={rel.id} style={{ textDecoration: 'none' }}>
                  <div className={`rel-card status-${status}`}>
                    <div className="rel-card-top">
                      <div>
                        <div className="rel-name">{rel.display_name || rel.qumulo_id}</div>
                        <div className="rel-path">{rel.cluster_name}</div>
                      </div>
                      {rel.end_reason
                        ? <span className="badge badge-error" title={rel.end_reason}>ended</span>
                        : !rel.enabled
                        ? <span className="badge badge-unknown">monitoring off</span>
                        : <StatusBadge status={status} />
                      }
                    </div>

                    {rel.source_path && (
                      <div className="rel-path" style={{ fontSize: 11 }}>
                        {rel.source_path} → {rel.target_host}{rel.target_path}
                      </div>
                    )}

                    <div className="rel-meta">
                      <div className="rel-meta-item">
                        <Clock size={11} />
                        {status === 'running' && rel.latest_raw_job_status
                          ? <JobProgressDisplay jobStatus={rel.latest_raw_job_status} compact />
                          : rel.replication_mode === 'REPLICATION_SNAPSHOT_POLICY'
                          ? <SnapshotQueueDisplay
                              queueCount={rel.replication_enabled == 0 ? 0 : (rel.latest_lag_seconds > 1000 ? 0 : rel.latest_lag_seconds)}
                              threshold={(rel.snapshot_queue_threshold ?? parseInt(settings.default_snapshot_queue_threshold) ?? 3)}
                            />
                          : <LagDisplay lagSeconds={rel.latest_lag_seconds} thresholdMinutes={rel.lag_threshold_minutes ?? threshold} />
                        }
                      </div>
                      <div className="rel-meta-item">
                        polled <RelativeTime ts={rel.last_polled_at} />
                      </div>
                    </div>

                    {rel.end_reason && (
                      <div style={{ fontSize: 11, color: 'var(--pomegranate-400)', padding: '4px 8px', background: 'var(--pomegranate-700)', borderRadius: 3, lineHeight: 1.4 }} title={rel.end_reason}>
                        <strong>Ended:</strong> {rel.end_reason.length > 100 ? rel.end_reason.slice(0, 100) + '…' : rel.end_reason}
                      </div>
                    )}
                    {!rel.end_reason && rel.latest_error && status === 'error' && (
                      <div style={{ fontSize: 11, color: 'var(--red)', fontFamily: 'var(--font-mono)', padding: '4px 8px', background: 'var(--red-bg)', borderRadius: 3, wordBreak: 'break-all' }}>
                        {rel.latest_error.slice(0, 120)}{rel.latest_error.length > 120 ? '…' : ''}
                      </div>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}
