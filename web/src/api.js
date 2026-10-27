// api.js — the one place the SPA talks to vigil's REST API. The API key is read
// once from the ?key= query param the server bakes into the opened URL, held in
// memory, and sent as a Bearer token on every request. SSE and report-download
// URLs carry it as ?key= because those cannot set a header.

const KEY = new URLSearchParams(location.search).get('key') || ''

function authHeaders(extra) {
  const h = { ...extra }
  if (KEY) h['Authorization'] = 'Bearer ' + KEY
  return h
}

async function req(method, path, body) {
  const opts = { method, headers: authHeaders(body ? { 'Content-Type': 'application/json' } : {}) }
  if (body !== undefined) opts.body = JSON.stringify(body)
  const r = await fetch('/api' + path, opts)
  if (!r.ok) {
    let msg = r.statusText || ('HTTP ' + r.status)
    try { const j = await r.json(); if (j && j.error) msg = j.error } catch {}
    const err = new Error(msg)
    err.status = r.status
    throw err
  }
  if (r.status === 204) return null
  const ct = r.headers.get('content-type') || ''
  return ct.includes('application/json') ? r.json() : r.text()
}

// withKey appends the API key as a query param for URLs the browser loads
// directly (SSE, report downloads).
function withKey(url) {
  if (!KEY) return url
  return url + (url.includes('?') ? '&' : '?') + 'key=' + encodeURIComponent(KEY)
}

export const api = {
  version: () => req('GET', '/version'),
  health: () => req('GET', '/health'),
  profiles: () => req('GET', '/profiles'),
  configDefaults: () => req('GET', '/config/defaults'),
  tools: () => req('GET', '/tools'),

  listScans: (offset = 0, limit = 200) => req('GET', `/scans?offset=${offset}&limit=${limit}`),
  getScan: (id) => req('GET', '/scans/' + id),
  createScan: (body) => req('POST', '/scans', body),
  cancelScan: (id) => req('DELETE', '/scans/' + id),
  findings: (id) => req('GET', `/scans/${id}/findings`),
  compliance: (id, framework) => req('GET', `/scans/${id}/compliance?framework=${encodeURIComponent(framework)}`),
  markFP: (id, fid, fp, reason) => req('POST', `/scans/${id}/findings/${fid}/fp`, { fp, reason }),

  listTargets: () => req('GET', '/targets'),
  createTarget: (url, label) => req('POST', '/targets', { url, label }),
  deleteTarget: (id) => req('DELETE', '/targets/' + id),
  scanTarget: (id, body) => req('POST', '/targets/' + id + '/scan', body || {}),

  getSettings: () => req('GET', '/settings'),
  putSettings: (cfg) => req('PUT', '/settings', cfg),

  // Direct-load URLs (browser follows these; key goes in the query string).
  reportURL: (id, format) => withKey(`/api/scans/${id}/report?format=${encodeURIComponent(format)}`),
  eventsURL: (id) => withKey(`/api/scans/${id}/events`),
}

export { KEY }
