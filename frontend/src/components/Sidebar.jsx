import { useState, useEffect } from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import { LayoutDashboard, Server, GitCompare, Bell, Settings, Users, LogOut } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useAppSettings } from '../hooks/useAppSettings';

export default function Sidebar() {
  const { user, logout, isAdmin } = useAuth();
  const { appName } = useAppSettings();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);

  useEffect(() => { setOpen(false); }, [location.pathname]);

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') setOpen(false); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const handleLogout = () => { logout(); navigate('/login'); };
  const navClass = ({ isActive }) => `nav-item${isActive ? ' active' : ''}`;

  return (
    <>
      <button
        className="hamburger"
        onClick={() => setOpen(o => !o)}
        aria-label="Toggle menu"
        style={{ display: 'none' }}
        id="hamburger-btn"
      >
        <span /><span /><span />
      </button>

      <div
        className={`sidebar-overlay${open ? ' active' : ''}`}
        onClick={() => setOpen(false)}
      />

      <aside className={`sidebar${open ? ' mobile-open' : ''}`}>
        <div className="sidebar-logo">
          <div className="logo-mark">◈ Qumulo</div>
          <div className="logo-name">{appName}</div>
        </div>

        <nav className="nav-section">
          <div className="nav-section-label">Monitor</div>
          <NavLink to="/" end className={navClass}>
            <LayoutDashboard size={15} /> Dashboard
          </NavLink>
          <NavLink to="/relationships" className={navClass}>
            <GitCompare size={15} /> Relationships
          </NavLink>
          <NavLink to="/alerts" className={navClass}>
            <Bell size={15} /> Alert Log
          </NavLink>
        </nav>

        {isAdmin && (
          <nav className="nav-section">
            <div className="nav-section-label">Admin</div>
            <NavLink to="/clusters" className={navClass}>
              <Server size={15} /> Clusters
            </NavLink>
            <NavLink to="/users" className={navClass}>
              <Users size={15} /> Users
            </NavLink>
            <NavLink to="/settings" className={navClass}>
              <Settings size={15} /> Settings
            </NavLink>
          </nav>
        )}

        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-avatar">{user?.username?.[0]?.toUpperCase()}</div>
            <div className="user-info">
              <div className="user-name">{user?.username}</div>
              <div className="user-role">{user?.role}</div>
            </div>
            <button className="logout-btn" title="Sign out" onClick={handleLogout}>
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
