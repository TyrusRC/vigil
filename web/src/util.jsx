import React from 'react'
import { I } from './icons'

export const SEV = ['critical', 'high', 'medium', 'low', 'info']
export const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function sevOf(f) { return (f.severity || 'info').toLowerCase() }

export function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }

export function highlight(text, marks) {
  if (!text) return ''
  let h = esc(text)
  for (const m of (marks || [])) {
    if (m && m.length > 2) {
      const e = esc(m)
      if (h.includes(e)) h = h.split(e).join(`<mark>${e}</mark>`)
    }
  }
  return h
}

export function Code({ text, marks }) {
  return <pre className="code-block" dangerouslySetInnerHTML={{ __html: highlight(text, marks) }} />
}

export function cvssBand(score) {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

export function copy(text) { try { navigator.clipboard?.writeText(text) } catch {} }

/* Build a shareable Markdown summary of a finding. */
export function findingToMarkdown(f) {
  const L = []
  L.push(`## ${f.type || f.title} [${sevOf(f).toUpperCase()}]`)
  L.push('')
  L.push(`- **URL:** ${f.url}`)
  if (f.parameter) L.push(`- **Parameter:** ${f.parameter}`)
  if (f.tool) L.push(`- **Source:** ${f.tool}`)
  if (f.cvss > 0) L.push(`- **CVSS:** ${Number(f.cvss).toFixed(1)}${f.cvss_vector ? ` (${f.cvss_vector})` : ''}`)
  if ((f.cwe || []).length) L.push(`- **CWE:** ${f.cwe.join(', ')}`)
  if ((f.wstg || []).length) L.push(`- **WSTG:** ${f.wstg.join(', ')}`)
  if (f.description) { L.push('', '### Description', f.description) }
  if (f.request) { L.push('', '### Request', '```http', f.request, '```') }
  if (f.remediation) { L.push('', '### Remediation', f.remediation) }
  return L.join('\n')
}

export function CurlCopy({ request, url, onCopy }) {
  const line = (request || '').split('\n')[0] || ''
  const m = line.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/)
  const method = m ? m[1] : 'GET', u = m ? m[2] : (url || '')
  const cmd = method === 'GET' ? `curl -k '${u}'` : `curl -k -X ${method} '${u}'`
  return (
    <div className="curl-block">
      <code>{cmd}</code>
      <button className="copy-btn" onClick={() => { copy(cmd); onCopy?.('curl command copied') }}><I.copy width="13" height="13" /> Copy</button>
    </div>
  )
}

/* Relative time for tables ("3m ago"). */
export function ago(iso) {
  if (!iso) return '—'
  const d = new Date(iso).getTime()
  if (isNaN(d)) return '—'
  const s = Math.floor((Date.now() - d) / 1000)
  if (s < 60) return s + 's ago'
  if (s < 3600) return Math.floor(s / 60) + 'm ago'
  if (s < 86400) return Math.floor(s / 3600) + 'h ago'
  return Math.floor(s / 86400) + 'd ago'
}
