// ── CYPHER AI · API Client ──────────────────────────────────
// Conecta ao backend Railway ou usa modo demo offline

const API_URL  = window.__CYPHER_API__  || 'https://cypher-ai-backend.up.railway.app'
const DEMO_MODE = !window.__CYPHER_API__ // true quando não há backend configurado

// ── HTTP helper ───────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const token = localStorage.getItem('cypher_access_token')
  try {
    const res = await fetch(`${API_URL}/api/v1${path}`, {
      ...opts,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...opts.headers,
      },
    })
    if (res.status === 401) {
      localStorage.clear()
      window.location.href = '/login.html'
      return null
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || `API error ${res.status}`)
    }
    return res.json()
  } catch (e) {
    if (DEMO_MODE) return null // silently fail in demo mode
    throw e
  }
}

// ── Auth ──────────────────────────────────────────────────────
const authApi = {
  login:   (email, password) => apiFetch('/auth/login', { method:'POST', body: JSON.stringify({ email, password }) }),
  me:      ()                => apiFetch('/auth/me'),
  refresh: (token)           => apiFetch('/auth/refresh', { method:'POST', body: JSON.stringify({ refresh_token: token }) }),
}

// ── Dashboard ─────────────────────────────────────────────────
const dashApi = {
  metrics: () => apiFetch('/dashboard/metrics'),
}

// ── Incidents ─────────────────────────────────────────────────
const incApi = {
  list:          (p)       => apiFetch('/incidents?' + new URLSearchParams(p || {}).toString()),
  get:           (id)      => apiFetch(`/incidents/${id}`),
  create:        (data)    => apiFetch('/incidents', { method:'POST', body: JSON.stringify(data) }),
  update:        (id,data) => apiFetch(`/incidents/${id}`, { method:'PATCH', body: JSON.stringify(data) }),
  messages:      (id)      => apiFetch(`/incidents/${id}/messages`),
  sendMessage:   (id,text) => apiFetch(`/incidents/${id}/messages`, { method:'POST', body: JSON.stringify({ content: text }) }),
  timeline:      (id)      => apiFetch(`/incidents/${id}/timeline`),
  actions:       (id)      => apiFetch(`/incidents/${id}/actions`),
  createAction:  (id,data) => apiFetch(`/incidents/${id}/actions`, { method:'POST', body: JSON.stringify(data) }),
  iocs:          (id)      => apiFetch(`/incidents/${id}/iocs`),
  addIoc:        (id,data) => apiFetch(`/incidents/${id}/iocs`, { method:'POST', body: JSON.stringify(data) }),
  report:        (id)      => apiFetch(`/incidents/${id}/report`, { method:'POST' }),
}

// ── Alerts ────────────────────────────────────────────────────
const alertApi = {
  list:  (p) => apiFetch('/alerts?' + new URLSearchParams(p || {}).toString()),
  stats: ()  => apiFetch('/alerts/stats'),
}

// ── Integrations ──────────────────────────────────────────────
const integApi = {
  list:   (cid) => apiFetch('/integrations' + (cid ? `?client_id=${cid}` : '')),
  create: (d)   => apiFetch('/integrations', { method:'POST', body: JSON.stringify(d) }),
  test:   (id)  => apiFetch(`/integrations/${id}/test`, { method:'POST' }),
  delete: (id)  => apiFetch(`/integrations/${id}`, { method:'DELETE' }),
}

// ── Clients ───────────────────────────────────────────────────
const clientApi = {
  list:   ()  => apiFetch('/organizations/clients'),
  create: (d) => apiFetch('/organizations/clients', { method:'POST', body: JSON.stringify(d) }),
}

// ── Playbooks ─────────────────────────────────────────────────
const playbookApi = {
  list:    ()  => apiFetch('/playbooks'),
  suggest: (d) => apiFetch('/playbooks/suggest', { method:'POST', body: JSON.stringify(d) }),
}

// ── Reports ───────────────────────────────────────────────────
const reportApi = {
  summary: (days) => apiFetch(`/reports/summary?days=${days || 30}`),
}

// NOTA: chamadas à Anthropic API devem passar pelo backend (/api/v1/incidents/:id/messages/stream)
// Nunca exponha API keys no frontend.

// ── Session helpers ───────────────────────────────────────────
function getUser()  { return JSON.parse(localStorage.getItem('cypher_user') || 'null') }
function getToken() { return localStorage.getItem('cypher_access_token') }
function isLoggedIn() { return !!getToken() }

function saveSession(data) {
  localStorage.setItem('cypher_access_token',  data.access_token)
  localStorage.setItem('cypher_refresh_token', data.refresh_token)
  localStorage.setItem('cypher_user',          JSON.stringify(data.user))
}

function clearSession() {
  localStorage.removeItem('cypher_access_token')
  localStorage.removeItem('cypher_refresh_token')
  localStorage.removeItem('cypher_user')
}

// Expose globally
window.CypherAPI = {
  auth: authApi, dash: dashApi, inc: incApi,
  alert: alertApi, integ: integApi, client: clientApi,
  playbook: playbookApi, report: reportApi,
  getUser, getToken, isLoggedIn,
  saveSession, clearSession, DEMO_MODE,
}
