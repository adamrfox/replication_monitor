import { useState, useEffect, useCallback } from 'react';
import { Bell, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/useToast';
import { Spinner, EmptyState, formatDate } from '../components/shared';

export default function AlertLogPage() {
  const { isAdmin } = useAuth();
  const { toast } = useToast();
  const [data, setData] = useState({ alerts: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const limit = 50;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.alertLog({ page, limit });
      setData(result);
    } catch (e) { toast(e.message, 'error'); }
    setLoading(false);
  }, [page]);
  useEffect(() => { load(); }, [load]);

  const handleAck = async (rel_id, alert_id) => {
    await api.acknowledgeAlert(rel_id, alert_id);
    toast('Alert acknowledged', 'success');
    load();
  };

  const handleAckAll = async () => {
    const result = await api.acknowledgeAllAlerts();
    toast(`${result.acknowledged} alert${result.acknowledged !== 1 ? 's' : ''} acknowledged`, 'success');
    load();
  };

  const unacknowledgedCount = data.alerts.filter(a => !a.acknowledged).length;

  const totalPages = Math.ceil(data.total / limit);

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Alert Log</div>
          <div className="page-subtitle">{data.total} total alerts across all relationships</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {isAdmin && unacknowledgedCount > 0 && (
            <button className="btn btn-secondary btn-sm" onClick={handleAckAll}>
              Acknowledge All ({unacknowledgedCount})
            </button>
          )}
          <button className="btn btn-secondary btn-sm" onClick={load}><RefreshCw size={13} /> Refresh</button>
        </div>
      </div>

      <div className="page-body">
        <div className="card">
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner /></div>
          ) : data.alerts.length === 0 ? (
            <EmptyState icon={<Bell size={40} />} title="No alerts" body="Alerts will appear here when replication issues are detected." />
          ) : (
            <>
              <table className="data-table">
                <thead>
                  <tr><th>Time</th><th>Type</th><th>Cluster</th><th>Relationship</th><th>Message</th><th>Status</th></tr>
                </thead>
                <tbody>
                  {data.alerts.map(a => (
                    <tr key={a.id} className={`alert-row-${a.alert_type}`}>
                      <td className="mono text-sm">{formatDate(a.sent_at)}</td>
                      <td>
                        <span className={`badge ${a.alert_type === 'error' ? 'badge-error' : a.alert_type === 'lag' ? 'badge-warning' : 'badge-ok'}`}>
                          {a.alert_type}
                        </span>
                      </td>
                      <td className="text-muted text-sm">{a.cluster_name || '—'}</td>
                      <td className="text-sm" style={{ color: 'var(--text-0)' }}>{a.relationship_name || a.relationship_id || '—'}</td>
                      <td className="text-sm text-muted" style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.message}</td>
                      <td>
                        {a.acknowledged ? (
                          <span className="text-muted text-sm">Ack'd by {a.acknowledged_by}</span>
                        ) : (
                          isAdmin && a.relationship_id
                            ? <button className="btn btn-ghost btn-sm" onClick={() => handleAck(a.relationship_id, a.id)}>Acknowledge</button>
                            : <span className="badge badge-error">Unacknowledged</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {totalPages > 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: 16, borderTop: '1px solid var(--border)' }}>
                  <button className="btn btn-secondary btn-sm" onClick={() => setPage(p => p - 1)} disabled={page === 0}>← Prev</button>
                  <span style={{ padding: '4px 12px', color: 'var(--text-2)', fontSize: 13 }}>Page {page + 1} of {totalPages}</span>
                  <button className="btn btn-secondary btn-sm" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}>Next →</button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </>
  );
}
