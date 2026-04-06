import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Server, GitCompare, Bell, Settings, Users, LogOut, Activity } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function Sidebar() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => { logout(); navigate('/login'); };

  const navClass = ({ isActive }) => `nav-item${isActive ? ' active' : ''}`;

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark">◈ Qumulo</div>
        <div className="logo-name">Replication Monitor</div>
        <div className="logo-sub">v1.0</div>
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
  );
}
