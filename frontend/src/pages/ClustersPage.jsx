import { useState, useEffect, useCallback } from 'react';
import { Server, Plus, Edit2, Trash2, Zap, Download, CheckCircle, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useToast } from '../hooks/useToast';
import { Modal, ConfirmModal, Spinner, EmptyState } from '../components/shared';

export default function ClustersPage() {
  const { toast } = useToast();
  const [clusters, setClusters] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [editCluster, setEditCluster] = useState(null);
  const [deleteCluster, setDeleteCluster] = useState(null);
  const [testResults, setTestResults] = useState({});
  const [discoverCluster, setDiscoverCluster] = useState(null);

  const load = useCallback(async () => {
    const data = await api.clusters();
    setClusters(data); setLoading(false);
  }, []);
  useEffect(() => { load(); }, [load]);

  const handleTest = async (cluster) => {
    setTestResults(r => ({ ...r, [cluster.id]: 'testing' }));
    const result = await api.testCluster(cluster.id);
    setTestResults(r => ({ ...r, [cluster.id]: result.success ? 'ok' : 'error' }));
    toast(result.success ? `Connected to ${cluster.name}` : result.error, result.success ? 'success' : 'error');
  };

  const handleDelete = async () => {
    await api.deleteCluster(deleteCluster.id);
    toast('Cluster deleted', 'success');
    setDeleteCluster(null); load();
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Clusters</div>
          <div className="page-subtitle">Manage Qumulo cluster connections</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setAddOpen(true)}>
          <Plus size={14} /> Add Cluster
        </button>
      </div>

      <div className="page-body">
        <div className="card">
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner /></div>
          ) : clusters.length === 0 ? (
            <EmptyState
              icon={<Server size={40} />}
              title="No clusters configured"
              body="Add a Qumulo cluster to start monitoring replication relationships."
              action={<button className="btn btn-primary btn-sm" onClick={() => setAddOpen(true)}><Plus size={13} /> Add Cluster</button>}
            />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th><th>Host</th><th>Port</th><th>SSL</th><th>API User</th><th>Added</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {clusters.map(c => (
                  <tr key={c.id}>
                    <td style={{ fontWeight: 600, color: 'var(--text-0)' }}>{c.name}</td>
                    <td className="mono text-sm">{c.host}</td>
                    <td className="mono text-sm">{c.port}</td>
                    <td>
                      <span className={`badge ${c.use_ssl ? 'badge-ok' : 'badge-warning'}`}>
                        {c.use_ssl ? 'HTTPS' : 'HTTP'}
                      </span>
                    </td>
                    <td className="mono text-sm text-muted">{c.api_username}</td>
                    <td className="text-muted text-sm">{new Date(c.created_at).toLocaleDateString()}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        {testResults[c.id] === 'testing' && <Spinner />}
                        {testResults[c.id] === 'ok' && <CheckCircle size={14} style={{ color: 'var(--green)' }} />}
                        {testResults[c.id] === 'error' && <XCircle size={14} style={{ color: 'var(--red)' }} />}
                        <button className="btn btn-ghost btn-icon btn-sm" title="Test connection" onClick={() => handleTest(c)}><Zap size={14} /></button>
                        <button className="btn btn-ghost btn-icon btn-sm" title="Discover relationships" onClick={() => setDiscoverCluster(c)}><Download size={14} /></button>
                        <button className="btn btn-ghost btn-icon btn-sm" title="Edit" onClick={() => setEditCluster(c)}><Edit2 size={14} /></button>
                        <button className="btn btn-ghost btn-icon btn-sm" title="Delete" onClick={() => setDeleteCluster(c)}><Trash2 size={14} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {addOpen && <ClusterFormModal onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); load(); }} />}
      {editCluster && <ClusterFormModal cluster={editCluster} onClose={() => setEditCluster(null)} onSaved={() => { setEditCluster(null); load(); }} />}
      {deleteCluster && (
        <ConfirmModal
          title="Delete Cluster"
          message={`Delete "${deleteCluster.name}" and all associated relationships and history?`}
          onConfirm={handleDelete}
          onClose={() => setDeleteCluster(null)}
        />
      )}
      {discoverCluster && <DiscoverModal cluster={discoverCluster} onClose={() => setDiscoverCluster(null)} onImported={() => { setDiscoverCluster(null); toast('Relationships imported', 'success'); }} />}
    </>
  );
}

// ─── Cluster Form ─────────────────────────────────────────────────────────────

function ClusterFormModal({ cluster, onClose, onSaved }) {
  const { toast } = useToast();
  const isEdit = !!cluster;
  const [form, setForm] = useState({
    name: cluster?.name || '',
    host: cluster?.host || '',
    port: cluster?.port || 8000,
    use_ssl: cluster?.use_ssl ?? true,
    api_username: cluster?.api_username || '',
    api_password: '',
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleTest = async () => {
    setTesting(true); setTestResult(null);
    try {
      const result = await api.testNewCluster({ ...form, use_ssl: form.use_ssl });
      setTestResult(result);
    } catch (e) { setTestResult({ success: false, error: e.message }); }
    setTesting(false);
  };

  const handleSave = async () => {
    if (!form.name || !form.host || !form.api_username) {
      toast('Name, host, and API username are required', 'error'); return;
    }
    if (!isEdit && !form.api_password) {
      toast('API password required', 'error'); return;
    }
    setSaving(true);
    try {
      const payload = { ...form };
      if (isEdit && !payload.api_password) delete payload.api_password;
      isEdit ? await api.updateCluster(cluster.id, payload) : await api.createCluster(payload);
      toast(isEdit ? 'Cluster updated' : 'Cluster added', 'success');
      onSaved();
    } catch (e) { toast(e.message, 'error'); }
    setSaving(false);
  };

  return (
    <Modal title={isEdit ? 'Edit Cluster' : 'Add Cluster'} onClose={onClose} footer={
      <>
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-secondary" onClick={handleTest} disabled={testing}>
          {testing ? <Spinner /> : <Zap size={13} />} Test
        </button>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
      </>
    }>
      {testResult && (
        <div className={testResult.success ? 'inline-success' : 'inline-error'}>
          {testResult.success ? '✓ Connection successful' : `✗ ${testResult.error}`}
        </div>
      )}
      <div className="form-group">
        <label className="form-label">Display Name</label>
        <input className="form-control" value={form.name} onChange={e => set('name', e.target.value)} placeholder="Production Cluster" />
      </div>
      <div className="form-row form-row-2">
        <div className="form-group">
          <label className="form-label">Host / IP</label>
          <input className="form-control form-control-mono" value={form.host} onChange={e => set('host', e.target.value)} placeholder="192.168.1.100" />
        </div>
        <div className="form-group">
          <label className="form-label">Port</label>
          <input className="form-control form-control-mono" type="number" value={form.port} onChange={e => set('port', parseInt(e.target.value))} />
        </div>
      </div>
      <div className="form-group">
        <div className="toggle-wrap">
          <label className="toggle">
            <input type="checkbox" checked={form.use_ssl} onChange={e => set('use_ssl', e.target.checked)} />
            <span className="toggle-slider" />
          </label>
          <span style={{ fontSize: 13, color: 'var(--text-1)' }}>Use HTTPS (SSL)</span>
        </div>
        <div className="form-hint">Disable for HTTP-only clusters. SSL cert validation is bypassed via proxy for self-signed certs.</div>
      </div>
      <div className="section-divider" />
      <div className="form-row form-row-2">
        <div className="form-group">
          <label className="form-label">API Username</label>
          <input className="form-control" value={form.api_username} onChange={e => set('api_username', e.target.value)} placeholder="admin" />
        </div>
        <div className="form-group">
          <label className="form-label">API Password {isEdit && <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>(leave blank to keep)</span>}</label>
          <input className="form-control" type="password" value={form.api_password} onChange={e => set('api_password', e.target.value)} placeholder={isEdit ? '••••••••' : ''} />
        </div>
      </div>
    </Modal>
  );
}

// ─── Discover Modal ───────────────────────────────────────────────────────────

function DiscoverModal({ cluster, onClose, onImported }) {
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [rels, setRels] = useState([]);
  const [selected, setSelected] = useState(new Set());
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api.discoverRelationships(cluster.id)
      .then(d => { setRels(d.relationships || []); setSelected(new Set((d.relationships || []).map(r => r.id))); })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [cluster.id]);

  const allIds = rels.map(r => r.id);
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id));

  const toggleAll = () => {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(allIds));
    }
  };

  const toggle = (id) => setSelected(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const handleImport = async () => {
    setImporting(true);
    try {
      const toImport = rels.filter(r => selected.has(r.id));
      await api.importDiscovered({ cluster_id: cluster.id, relationships: toImport });
      onImported();
    } catch (e) { toast(e.message, 'error'); }
    setImporting(false);
  };

  return (
    <Modal title={`Discover Relationships — ${cluster.name}`} onClose={onClose} size="lg" footer={
      <>
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleImport} disabled={importing || selected.size === 0}>
          {importing ? 'Importing…' : `Import ${selected.size} selected`}
        </button>
      </>
    }>
      {loading && <div style={{ display: 'flex', justifyContent: 'center', padding: 30 }}><Spinner /></div>}
      {error && <div className="inline-error">{error}</div>}
      {!loading && !error && rels.length === 0 && <p className="text-muted text-sm">No relationships found on this cluster.</p>}
      {!loading && !error && rels.length > 0 && (
        <div
          style={{ padding: '8px 14px 12px', borderBottom: '1px solid var(--blackberry-700)', display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}
          onClick={toggleAll}
        >
          <input type="checkbox" className="discover-item-check" checked={allSelected} onChange={toggleAll} />
          <span style={{ fontSize: 13, color: 'var(--lychee-400)', fontWeight: 500 }}>
            {allSelected ? 'Deselect all' : 'Select all'} ({rels.length})
          </span>
        </div>
      )}
      {rels.map(r => {
        const label = r.display_name || r.name || r.id;
        const target = [r.target_address || r.target_host, r.target_port ? `:${r.target_port}` : ''].filter(Boolean).join('');
        const sourcePath = r.source_root_path || r.source_path || r.source_root_id || '';
        const targetPath = r.target_root_path || r.target_path || '';
        const mode = r.replication_mode ? r.replication_mode.replace('REPLICATION_', '').toLowerCase() : '';
        return (
          <div key={r.id} className={`discover-item ${selected.has(r.id) ? 'selected' : ''}`} onClick={() => toggle(r.id)} style={{ opacity: r.replication_enabled === false ? 0.7 : 1 }}>
            <input type="checkbox" className="discover-item-check" checked={selected.has(r.id)} readOnly />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--lychee-100)' }}>{label}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-2)', marginTop: 2 }}>
                {target && <span>&#8594; {target}{targetPath}</span>}
                {sourcePath && <span style={{ marginLeft: 8 }}>src: {sourcePath}</span>}
              </div>
              {mode && <div style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 2 }}>{mode}</div>}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
              <span className={`badge ${r.direction === 'source' ? 'badge-running' : 'badge-viewer'}`}>{r.direction}</span>
              {r.replication_enabled === false && <span className="badge badge-unknown">disabled</span>}
            </div>
          </div>
        );
      })}
    </Modal>
  );
}
