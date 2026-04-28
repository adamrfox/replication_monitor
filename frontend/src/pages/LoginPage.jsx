import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useAppSettings } from '../hooks/useAppSettings';

export default function LoginPage() {
  const { login } = useAuth();
  const { appName } = useAppSettings();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      await login(form.username, form.password);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-box">
        <div className="login-header">
          <div className="login-logo">◈ Qumulo</div>
          <div className="login-title">{appName}</div>
          <div className="login-sub">Sign in to continue</div>
        </div>
        <div className="login-card">
          {error && <div className="inline-error" style={{ marginBottom: 16 }}>{error}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                className="form-control"
                type="text"
                autoFocus
                autoComplete="username"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="admin"
              />
            </div>
            <div className="form-group" style={{ marginBottom: 20 }}>
              <label className="form-label">Password</label>
              <input
                className="form-control"
                type="password"
                autoComplete="current-password"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                placeholder="••••••••"
              />
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading} style={{ width: '100%', justifyContent: 'center' }}>
              {loading ? <><span className="spinner" style={{ width: 14, height: 14 }} /> Signing in…</> : 'Sign In'}
            </button>
          </form>
          <p style={{ marginTop: 16, textAlign: 'center', fontSize: 11, color: 'var(--text-3)' }}>
            Default: admin / admin — change after first login
          </p>
        </div>
      </div>
    </div>
  );
}
