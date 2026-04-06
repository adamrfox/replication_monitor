import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './hooks/useAuth';
import { ToastProvider } from './hooks/useToast';
import Sidebar from './components/Sidebar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import { RelationshipsPage, RelationshipDetailPage } from './pages/RelationshipsPage';
import ClustersPage from './pages/ClustersPage';
import UsersPage from './pages/UsersPage';
import SettingsPage from './pages/SettingsPage';
import AlertLogPage from './pages/AlertLogPage';

function RequireAuth({ children }) {
  const { user, loading } = useAuth();
  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: 'var(--bg-0)' }}>
      <span className="spinner" style={{ width: 28, height: 28 }} />
    </div>
  );
  return user ? children : <Navigate to="/login" replace />;
}

function RequireAdmin({ children }) {
  const { user } = useAuth();
  return user?.role === 'admin' ? children : <Navigate to="/" replace />;
}

function AppLayout() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main-content">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/relationships" element={<RelationshipsPage />} />
          <Route path="/relationships/:id" element={<RelationshipDetailPage />} />
          <Route path="/alerts" element={<AlertLogPage />} />
          <Route path="/clusters" element={<RequireAdmin><ClustersPage /></RequireAdmin>} />
          <Route path="/users" element={<RequireAdmin><UsersPage /></RequireAdmin>} />
          <Route path="/settings" element={<RequireAdmin><SettingsPage /></RequireAdmin>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/*" element={<RequireAuth><AppLayout /></RequireAuth>} />
          </Routes>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
