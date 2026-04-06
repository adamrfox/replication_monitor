import { useState, useEffect, useCallback } from 'react';
import { Users, Plus, Edit2, Trash2, Key } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../hooks/useToast';
import { Modal, ConfirmModal, Spinner, EmptyState, formatDate } from '../components/shared';

export default function UsersPage() {
  const { user: me } = useAuth();
  const { toast } = useToast();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [deleteUser, setDeleteUser] = useState(null);
  const [pwUser, setPwUser] = useState(null);

  const load = useCallback(async () => {
    const data = await api.users();
    setUsers(data); setLoading(false);
  }, []);
  useEffect(() => { load(); }, [load]);

  const handleDelete = async () => {
    try {
      await api.deleteUser(deleteUser.id);
      toast('User deleted', 'success');
      setDeleteUser(null); load();
    } catch (e) { toast(e.message, 'error'); }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Users</div>
          <div className="page-subtitle">Manage access to the monitoring system</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setAddOpen(true)}>
          <Plus size={14} /> Add User
        </button>
      </div>

      <div className="page-body">
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-body" style={{ padding: '12px 18px' }}>
            <p style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6 }}>
              <strong style={{ color: 'var(--accent)' }}>Admin</strong> users can manage clusters, relationships, users, and settings.{' '}
              <strong style={{ color: 'var(--text-0)' }}>Viewer</strong> users can view the dashboard, relationships, and alert log but cannot make changes.
            </p>
          </div>
        </div>

        <div className="card">
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><Spinner /></div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>Username</th><th>Role</th><th>Email</th><th>Last Login</th><th>Created</th><th>Actions</th></tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id}>
                    <td style={{ fontWeight: 500, color: 'var(--text-0)' }}>
                      {u.username}
                      {u.id === me.id && <span className="badge badge-unknown" style={{ marginLeft: 6 }}>you</span>}
                    </td>
                    <td>
                      <span className={`badge ${u.role === 'admin' ? 'badge-admin' : 'badge-viewer'}`}>{u.role}</span>
                    </td>
                    <td className="text-muted text-sm">{u.email || '—'}</td>
                    <td className="text-muted text-sm">{u.last_login ? formatDate(u.last_login) : 'Never'}</td>
                    <td className="text-muted text-sm">{new Date(u.created_at).toLocaleDateString()}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-ghost btn-icon btn-sm" title="Change password" onClick={() => setPwUser(u)}><Key size={14} /></button>
                        <button className="btn btn-ghost btn-icon btn-sm" title="Edit" onClick={() => setEditUser(u)}><Edit2 size={14} /></button>
                        {u.id !== me.id && (
                          <button className="btn btn-ghost btn-icon btn-sm" title="Delete" onClick={() => setDeleteUser(u)}><Trash2 size={14} /></button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {addOpen && <UserFormModal onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); load(); }} />}
      {editUser && <UserFormModal user={editUser} onClose={() => setEditUser(null)} onSaved={() => { setEditUser(null); load(); }} />}
      {deleteUser && (
        <ConfirmModal
          title="Delete User"
          message={`Delete user "${deleteUser.username}"? This cannot be undone.`}
          onConfirm={handleDelete}
          onClose={() => setDeleteUser(null)}
        />
      )}
      {pwUser && <ChangePasswordModal user={pwUser} onClose={() => setPwUser(null)} />}
    </>
  );
}

function UserFormModal({ user, onClose, onSaved }) {
  const { toast } = useToast();
  const isEdit = !!user;
  const [form, setForm] = useState({
    username: user?.username || '',
    password: '',
    role: user?.role || 'viewer',
    email: user?.email || '',
  });
  const [saving, setSaving] = useState(false);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    if (!isEdit && (!form.username || !form.password)) { toast('Username and password required', 'error'); return; }
    if (form.password && form.password.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
    setSaving(true);
    try {
      const payload = { ...form };
      if (isEdit && !payload.password) delete payload.password;
      isEdit ? await api.updateUser(user.id, payload) : await api.createUser(payload);
      toast(isEdit ? 'User updated' : 'User created', 'success');
      onSaved();
    } catch (e) { toast(e.message, 'error'); }
    setSaving(false);
  };

  return (
    <Modal title={isEdit ? `Edit User: ${user.username}` : 'Add User'} onClose={onClose} footer={
      <><button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button></>
    }>
      <div className="form-group">
        <label className="form-label">Username</label>
        <input className="form-control" value={form.username} onChange={e => set('username', e.target.value)} disabled={isEdit} />
      </div>
      {!isEdit && (
        <div className="form-group">
          <label className="form-label">Password</label>
          <input className="form-control" type="password" value={form.password} onChange={e => set('password', e.target.value)} />
          <div className="form-hint">Minimum 8 characters.</div>
        </div>
      )}
      <div className="form-group">
        <label className="form-label">Role</label>
        <select className="form-control" value={form.role} onChange={e => set('role', e.target.value)}>
          <option value="viewer">Viewer — can view only</option>
          <option value="admin">Admin — full access</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Email (optional)</label>
        <input className="form-control" type="email" value={form.email} onChange={e => set('email', e.target.value)} placeholder="user@example.com" />
        <div className="form-hint">Used for account identification only, not for alerts.</div>
      </div>
    </Modal>
  );
}

function ChangePasswordModal({ user, onClose }) {
  const { user: me } = useAuth();
  const { toast } = useToast();
  const isSelf = user.id === me.id;
  const [form, setForm] = useState({ current_password: '', new_password: '', confirm: '' });
  const [saving, setSaving] = useState(false);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSave = async () => {
    if (form.new_password.length < 8) { toast('Min 8 characters', 'error'); return; }
    if (form.new_password !== form.confirm) { toast('Passwords do not match', 'error'); return; }
    setSaving(true);
    try {
      if (isSelf) {
        await api.changePassword({ current_password: form.current_password, new_password: form.new_password });
      } else {
        await api.updateUser(user.id, { password: form.new_password });
      }
      toast('Password changed', 'success'); onClose();
    } catch (e) { toast(e.message, 'error'); }
    setSaving(false);
  };

  return (
    <Modal title={`Change Password — ${user.username}`} onClose={onClose} footer={
      <><button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleSave} disabled={saving}>{saving ? 'Saving…' : 'Change Password'}</button></>
    }>
      {isSelf && (
        <div className="form-group">
          <label className="form-label">Current Password</label>
          <input className="form-control" type="password" value={form.current_password} onChange={e => set('current_password', e.target.value)} />
        </div>
      )}
      <div className="form-group">
        <label className="form-label">New Password</label>
        <input className="form-control" type="password" value={form.new_password} onChange={e => set('new_password', e.target.value)} />
      </div>
      <div className="form-group">
        <label className="form-label">Confirm New Password</label>
        <input className="form-control" type="password" value={form.confirm} onChange={e => set('confirm', e.target.value)} />
      </div>
    </Modal>
  );
}
