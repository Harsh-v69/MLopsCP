// Thin fetch wrapper over the MLShield backend (src/api/main.py).
// No caching, no client-side recomputation of any value the backend
// already computed - the whole point of Phase 9's gate is that the
// dashboard shows exactly what the backend says, not a derived copy.
const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  })

  if (!response.ok) {
    let detail = response.statusText
    try {
      const body = await response.json()
      detail = body.detail || JSON.stringify(body)
    } catch {
      // response wasn't JSON - keep statusText
    }
    const error = new Error(detail)
    error.status = response.status
    throw error
  }

  return response.json()
}

export const api = {
  getSecurityGate: () => request('/security-gate'),
  getModelCard: () => request('/model-card'),
  getAuditLog: (token) =>
    request('/audit-log', { headers: { Authorization: `Bearer ${token}` } }),
  getDevToken: (subject, role) =>
    request(`/auth/dev-token?subject=${encodeURIComponent(subject)}&role=${encodeURIComponent(role)}`, {
      method: 'POST',
    }),
  explain: (records) =>
    request('/predict/explain', { method: 'POST', body: JSON.stringify({ records }) }),
}
