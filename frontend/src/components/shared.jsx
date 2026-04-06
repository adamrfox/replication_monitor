import { X } from 'lucide-react';

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
