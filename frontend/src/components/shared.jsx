import { X } from 'lucide-react';

/**
 * Derive the display status for a relationship — single source of truth
 * used by both the dashboard cards and the detail page header.
 * rel must have: end_reason, replication_enabled, latest_status (or status),
 *                replication_mode, lag_seconds (or latest_lag_seconds),
 *                lag_threshold_minutes, snapshot_queue_threshold
 * defaultThreshold: system default lag threshold in minutes
 * defaultSnapshotThreshold: system default snapshot queue threshold
 */
export function deriveStatus(rel, defaultThreshold = 60, defaultSnapshotThreshold = 3) {
  if (rel.end_reason) return 'ended';
  const clusterDisabled = rel.replication_enabled == 0 && rel.replication_enabled !== null;
  const latestStatus = rel.latest_status || rel.status;
  if (!latestStatus) return clusterDisabled ? 'disabled' : 'unknown';
  if (latestStatus === 'error') return 'error';
  if (latestStatus === 'disabled' || clusterDisabled) return 'disabled';
  if (latestStatus === 'running') return 'running';
  const isSnapshot = rel.replication_mode === 'REPLICATION_SNAPSHOT_POLICY';
  if (!isSnapshot) {
    const lag = rel.lag_seconds ?? rel.latest_lag_seconds;
    const thresh = (rel.lag_threshold_minutes ?? defaultThreshold) * 60;
    if (lag !== null && lag !== undefined && lag > thresh) return 'warning';
  }
  return 'ok';
}

export function Modal({ title, onClose, children, footer, size = '' }) {
  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${size === 'lg' ? 'modal-lg' : ''}`}>
        <div className="modal-header">
          <span className="modal-title">{title}</span>
          <button className="btn btn-ghost btn-icon btn-sm" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

export function StatusBadge({ status }) {
  const map = {
    ok:       { cls: 'badge-ok',      dot: 'ok',      label: 'OK' },
    running:  { cls: 'badge-running', dot: 'running', label: 'RUNNING' },
    warning:  { cls: 'badge-warning', dot: 'warning', label: 'LAGGING' },
    error:    { cls: 'badge-error',   dot: 'error',   label: 'ERROR' },
    disabled: { cls: 'badge-warning', dot: 'unknown', label: 'DISABLED' },
    ended:    { cls: 'badge-error',   dot: 'unknown', label: 'ENDED' },
    unknown:  { cls: 'badge-unknown', dot: 'unknown', label: 'UNKNOWN' },
  };
  const s = map[status] || map.unknown;
  return (
    <span className={`badge ${s.cls}`}>
      <span className={`status-dot ${s.dot}`} />
      {s.label}
    </span>
  );
}

export function Spinner() {
  return <span className="spinner" />;
}

export function EmptyState({ icon, title, body, action }) {
  return (
    <div className="empty-state">
      {icon}
      <strong style={{ color: 'var(--text-1)', fontSize: 14 }}>{title}</strong>
      {body && <p>{body}</p>}
      {action}
    </div>
  );
}

export function ConfirmModal({ title, message, onConfirm, onClose, danger = true }) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} onClick={onConfirm}>Confirm</button>
        </>
      }
    >
      <p style={{ color: 'var(--text-1)', lineHeight: 1.6 }}>{message}</p>
    </Modal>
  );
}

/**
 * Display lag time for continuous replication relationships.
 * lagSeconds = seconds since last successful replication.
 * thresholdMinutes = alert threshold in minutes.
 */
export function LagDisplay({ lagSeconds, thresholdMinutes }) {
  if (lagSeconds === null || lagSeconds === undefined) return <span className="text-muted">—</span>;
  const mins = Math.round(lagSeconds / 60);
  const pct = thresholdMinutes ? Math.min(100, (mins / thresholdMinutes) * 100) : 0;
  const color = pct >= 100 ? 'var(--red)' : pct >= 80 ? 'var(--yellow)' : 'var(--green)';

  return (
    <div className="lag-bar-wrap" style={{ minWidth: 120 }}>
      <span className="mono text-sm" style={{ color, minWidth: 54 }}>
        {mins < 60 ? `${mins}m` : `${Math.floor(mins / 60)}h${mins % 60}m`}
      </span>
      <div className="lag-bar">
        <div className="lag-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

/**
 * Display queued snapshot count for snapshot-policy replication relationships.
 * queueCount = number of queued snapshots (stored in lag_seconds column).
 * threshold = alert threshold (number of snapshots).
 */
export function SnapshotQueueDisplay({ queueCount, threshold }) {
  if (queueCount === null || queueCount === undefined) return <span className="text-muted">—</span>;
  const t = threshold || 3;
  const pct = Math.min(100, (queueCount / t) * 100);
  const color = pct >= 100 ? 'var(--red)' : pct >= 80 ? 'var(--yellow)' : 'var(--green)';

  return (
    <div className="lag-bar-wrap" style={{ minWidth: 120 }}>
      <span className="mono text-sm" style={{ color, minWidth: 54 }}>
        {queueCount} / {t}
      </span>
      <div className="lag-bar">
        <div className="lag-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

/**
 * Format bytes into human-readable string.
 */
function fmtBytes(val) {
  const n = parseInt(val);
  if (isNaN(n)) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

/**
 * Format throughput bytes/sec into human-readable string.
 */
function fmtThroughput(val) {
  const n = parseInt(val);
  if (isNaN(n)) return '—';
  if (n < 1024) return n + ' B/s';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB/s';
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB/s';
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB/s';
}

/**
 * Display active replication job progress.
 * jobStatus = replication_job_status object from Qumulo API.
 * compact = show minimal one-line version for table/card.
 */
export function JobProgressDisplay({ jobStatus, compact = false }) {
  if (!jobStatus) return null;
  const pct = (jobStatus.percent_complete || 0) * 100;
  const color = pct >= 100 ? 'var(--green)' : 'var(--agave-400)';

  if (compact) {
    return (
      <div className="lag-bar-wrap" style={{ minWidth: 140 }}>
        <span className="mono text-sm" style={{ color, minWidth: 42 }}>{pct.toFixed(1)}%</span>
        <div className="lag-bar">
          <div className="lag-bar-fill" style={{ width: `${Math.min(100, pct)}%`, background: color }} />
        </div>
        <span className="text-sm text-muted" style={{ whiteSpace: 'nowrap' }}>
          {fmtThroughput(jobStatus.throughput_current)}
        </span>
      </div>
    );
  }

  const estSecs = parseInt(jobStatus.estimated_seconds_remaining);
  const estLabel = !isNaN(estSecs)
    ? estSecs < 60 ? `${estSecs}s remaining`
    : estSecs < 3600 ? `${Math.round(estSecs / 60)}m remaining`
    : `${Math.round(estSecs / 3600)}h remaining`
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Progress bar */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
          <span style={{ color, fontWeight: 600 }}>{pct.toFixed(1)}% complete</span>
          {estLabel && <span className="text-muted">{estLabel}</span>}
        </div>
        <div className="lag-bar" style={{ height: 6 }}>
          <div className="lag-bar-fill" style={{ width: `${Math.min(100, pct)}%`, background: color }} />
        </div>
      </div>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 20px', fontSize: 12 }}>
        {[
          ['Transferred', fmtBytes(jobStatus.bytes_transferred)],
          ['Remaining', fmtBytes(jobStatus.bytes_remaining)],
          ['Total', fmtBytes(jobStatus.bytes_total)],
          ['Deleted', fmtBytes(jobStatus.bytes_deleted)],
          ['Files Transferred', jobStatus.files_transferred],
          ['Files Remaining', jobStatus.files_remaining],
          ['Files Total', jobStatus.files_total],
          ['Throughput (now)', fmtThroughput(jobStatus.throughput_current)],
          ['Throughput (avg)', fmtThroughput(jobStatus.throughput_overall)],
        ].map(([label, val]) => val && val !== '—' && (
          <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <span className="text-muted">{label}</span>
            <span className="mono" style={{ color: 'var(--lychee-100)' }}>{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Parse a timestamp string that may or may not have a UTC 'Z' suffix.
 * SQLite CURRENT_TIMESTAMP stores without 'Z'; explicit ISO strings have it.
 * Without 'Z', JS interprets as local time — we always want UTC interpretation.
 */
export function parseUtcDate(ts) {
  if (!ts) return null;
  const str = String(ts);
  // Already has timezone info
  if (str.endsWith('Z') || str.includes('+') || str.match(/[+-]\d{2}:\d{2}$/)) {
    return new Date(str);
  }
  // SQLite CURRENT_TIMESTAMP format: "YYYY-MM-DD HH:MM:SS" — treat as UTC
  return new Date(str.replace(' ', 'T') + 'Z');
}

export function formatDate(ts) {
  const d = parseUtcDate(ts);
  if (!d || isNaN(d.getTime())) return '—';
  // toLocaleString uses the browser's local timezone automatically
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    timeZoneName: 'short',
  });
}

export function RelativeTime({ ts }) {
  const d = parseUtcDate(ts);
  if (!d || isNaN(d.getTime())) return <span className="text-muted">Never</span>;
  const secs = Math.round((Date.now() - d.getTime()) / 1000);
  let label;
  if (secs < 0)         label = 'just now';
  else if (secs < 60)   label = `${secs}s ago`;
  else if (secs < 3600) label = `${Math.round(secs / 60)}m ago`;
  else if (secs < 86400) label = `${Math.round(secs / 3600)}h ago`;
  else                  label = `${Math.round(secs / 86400)}d ago`;
  return <span title={d.toLocaleString()}>{label}</span>;
}
