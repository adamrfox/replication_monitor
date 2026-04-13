const BASE = '/api';

function getToken() {
  return localStorage.getItem('qm_token');
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  if (res.status === 401) {
    localStorage.removeItem('qm_token');
    localStorage.removeItem('qm_user');
    window.location.href = '/login';
    return;
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { status: res.status, data });
  return data;
}

export const api = {
  // Auth
  login: (username, password) => apiFetch('/auth/login', { method: 'POST', body: { username, password } }),
  me: () => apiFetch('/auth/me'),
  users: () => apiFetch('/auth/users'),
  createUser: (data) => apiFetch('/auth/users', { method: 'POST', body: data }),
  updateUser: (id, data) => apiFetch(`/auth/users/${id}`, { method: 'PUT', body: data }),
  deleteUser: (id) => apiFetch(`/auth/users/${id}`, { method: 'DELETE' }),
  changePassword: (data) => apiFetch('/auth/change-password', { method: 'PUT', body: data }),

  // Clusters
  clusters: () => apiFetch('/clusters'),
  createCluster: (data) => apiFetch('/clusters', { method: 'POST', body: data }),
  updateCluster: (id, data) => apiFetch(`/clusters/${id}`, { method: 'PUT', body: data }),
  deleteCluster: (id) => apiFetch(`/clusters/${id}`, { method: 'DELETE' }),
  testCluster: (id) => apiFetch(`/clusters/${id}/test`, { method: 'POST' }),
  testNewCluster: (data) => apiFetch('/clusters/test-new', { method: 'POST', body: data }),
  discoverRelationships: (id) => apiFetch(`/clusters/${id}/discover`),

  // Relationships
  relationships: () => apiFetch('/relationships'),
  relationship: (id) => apiFetch(`/relationships/${id}`),
  createRelationship: (data) => apiFetch('/relationships', { method: 'POST', body: data }),
  updateRelationship: (id, data) => apiFetch(`/relationships/${id}`, { method: 'PUT', body: data }),
  deleteRelationship: (id) => apiFetch(`/relationships/${id}`, { method: 'DELETE' }),
  importDiscovered: (data) => apiFetch('/relationships/import-discovered', { method: 'POST', body: data }),
  acknowledgeAlert: (relId, alertId) => apiFetch(`/relationships/${relId}/alerts/${alertId}/acknowledge`, { method: 'POST' }),
  acknowledgeAllRelAlerts: (relId) => apiFetch(`/relationships/${relId}/alerts/acknowledge-all`, { method: 'POST' }),

  // Settings
  settings: () => apiFetch('/settings'),
  updateSettings: (data) => apiFetch('/settings', { method: 'PUT', body: data }),
  testSmtp: (data) => apiFetch('/settings/test-smtp', { method: 'POST', body: data }),
  sendTestAlert: () => apiFetch('/settings/send-test-alert', { method: 'POST' }),
  alertLog: (params = {}) => apiFetch(`/settings/alerts?${new URLSearchParams(params)}`),
  acknowledgeAllAlerts: () => apiFetch('/settings/alerts/acknowledge-all', { method: 'POST' }),
  purgeAlerts: (days) => apiFetch('/settings/alerts/purge', { method: 'POST', body: { days } }),
  purgeAllAlerts: () => apiFetch('/settings/alerts/purge-all', { method: 'POST' }),
};
