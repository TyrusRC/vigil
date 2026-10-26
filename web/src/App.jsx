import React, { useEffect, useMemo, useRef, useState, useCallback } from 'react'

const SEV = ['critical', 'high', 'medium', 'low', 'info']
const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const TAB_KEYS = ['request', 'response', 'details', 'remediation']

/* ── Icons (inline SVG, no emoji) ─────────────────── */
const I = {
  shield: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  search: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" {...p}><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>,
  copy: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" {...p}><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>,
  target: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" {...p}><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>,
  bug: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="m8 2 1.88 1.88M14.12 3.88 16 2M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6zM12 20v-9M6.53 9C4.6 8.8 3 7.1 3 5M6 13H2M3 21c0-2.1 1.7-3.9 3.8-4M20.97 5c0 2.1-1.6 3.8-3.5 4M22 13h-4M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>,
  activity: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>,
  sun: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>,
  moon: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"/></svg>,
  check: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M20 6 9 17l-5-5"/></svg>,
  xcircle: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/></svg>,
  link: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg>,
  keyboard: (p) => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...p}><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10h0M10 10h0M14 10h0M18 10h0M6 14h0M18 14h0M10 14h4"/></svg>,
}

function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }
function highlight(text, marks) {
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

function Code({ text, marks }) {
  return <pre className="code-block" dangerouslySetInnerHTML={{ __html: highlight(text, marks) }} />
}

function cvssBand(score) {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

/* Build a shareable Markdown summary of a finding. */
function findingToMarkdown(f) {
  const L = []
  L.push(`## ${f.type || f.title} [${(f.severity || 'info').toUpperCase()}]`)
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

function copy(text) { try { navigator.clipboard?.writeText(text) } catch {} }

function CurlCopy({ request, url, onCopy }) {
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

/* ── Finding detail ───────────────────────────────── */
function Detail({ f, tab, setTab, triage, setTriageFor, onToast }) {
  if (!f) return (
    <div className="empty-state">
      <I.bug width="56" height="56" />
      <p>Select a finding to inspect evidence and remediation</p>
      <p className="hint-line"><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>/</kbd> search · <kbd>1</kbd>–<kbd>4</kbd> tabs</p>
    </div>
  )

  const sev = (f.severity || 'info').toLowerCase()
  const marks = [f.parameter, f.evidence].filter(Boolean)
  const cvss = f.cvss_vector || ''
  const score = f.cvss || 0
  const band = cvssBand(score)
  const state = triage[f.id] || 'open'

  const labels = { request: 'Request', response: 'Response', details: 'Details', remediation: 'Remediation' }

  return (
    <div className={`detail-card ${state === 'fp' ? 'is-fp' : ''}`}>
      <div className="detail-header">
        <div className="dh-top">
          <span className={`badge ${sev}`}>{LABELS[sev]}</span>
          <h2>{f.type || f.title}</h2>
          <div className="dh-actions">
            <button className={`chip-btn ${state === 'reviewed' ? 'on ok' : ''}`} aria-pressed={state === 'reviewed'}
              title="Mark reviewed (r)" onClick={() => { setTriageFor(f.id, state === 'reviewed' ? 'open' : 'reviewed'); onToast(state === 'reviewed' ? 'Reopened' : 'Marked reviewed') }}>
              <I.check width="14" height="14" /> Reviewed
            </button>
            <button className={`chip-btn ${state === 'fp' ? 'on bad' : ''}`} aria-pressed={state === 'fp'}
              title="Mark false positive (f)" onClick={() => { setTriageFor(f.id, state === 'fp' ? 'open' : 'fp'); onToast(state === 'fp' ? 'Restored' : 'Marked false positive') }}>
              <I.xcircle width="14" height="14" /> False positive
            </button>
            <button className="chip-btn" title="Copy URL (y)" onClick={() => { copy(f.url); onToast('URL copied') }}><I.link width="14" height="14" /> URL</button>
            <button className="chip-btn" title="Copy as Markdown (c)" onClick={() => { copy(findingToMarkdown(f)); onToast('Finding copied as Markdown') }}><I.copy width="14" height="14" /> Copy</button>
          </div>
        </div>
        <div className="detail-meta">
          <span><b>URL</b> <span className="mono">{f.url}</span></span>
          {f.parameter && <span><b>Param</b> <span className="mono">{f.parameter}</span></span>}
          {f.tool && <span><b>Source</b> <span className="mono">{f.tool}</span></span>}
          {f.confidence && <span><b>Confidence</b> {f.confidence}</span>}
          {f.verified && <span className="verified">✓ Verified</span>}
          {state !== 'open' && <span className={`triage-flag ${state}`}>{state === 'fp' ? '✕ False positive' : '✓ Reviewed'}</span>}
        </div>
        {(score > 0 || cvss) && (
          <div className="cvss-bar">
            <div className={`cvss-score sev-${band}`}>{score > 0 ? score.toFixed(1) : '—'}<span className="cvss-max">CVSS</span></div>
            <div className="cvss-detail">
              <span className="cvss-label">CVSS 3.1 Vector</span>
              <code className="cvss-vector">{cvss || 'not provided'}</code>
            </div>
          </div>
        )}
      </div>

      <div className="tabs" role="tablist">
        {TAB_KEYS.map((k, i) => (
          <div key={k} role="tab" aria-selected={tab === k} tabIndex={0} className={`tab ${tab === k ? 'active' : ''}`}
            onClick={() => setTab(k)} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setTab(k)}>
            <span className="tab-num">{i + 1}</span>{labels[k]}
            {k === 'request' && f.request && <span className="tab-dot" />}
            {k === 'response' && (f.response || f.evidence) && <span className="tab-dot" />}
          </div>
        ))}
      </div>

      <div className="tab-content">
        {tab === 'request' && <>
          {f.request ? <Code text={f.request} marks={marks} />
            : <div className="no-data">No raw HTTP request captured for this finding.{f.evidence && <><br /><br /><b>Evidence:</b> {f.evidence}</>}</div>}
          <CurlCopy request={f.request} url={f.url} onCopy={onToast} />
        </>}
        {tab === 'response' && <>
          {f.response ? <Code text={f.response} marks={marks} />
            : f.evidence ? <><p className="section-label">Evidence</p><Code text={f.evidence} marks={[f.parameter]} /></>
              : <div className="no-data">No HTTP response captured.</div>}
        </>}
        {tab === 'details' && <>
          {f.description && <p className="description">{f.description}</p>}
          <div className="detail-grid">
            {(f.cwe || []).length > 0 && <div><p className="section-label">CWE</p><div className="tags">{f.cwe.map(c => <span key={c} className="tag">{c}</span>)}</div></div>}
            {(f.wstg || []).length > 0 && <div><p className="section-label">OWASP WSTG</p><div className="tags">{f.wstg.map(w => <span key={w} className="tag">{w}</span>)}</div></div>}
            {(f.top10 || []).length > 0 && <div><p className="section-label">OWASP Top 10</p><div className="tags">{f.top10.map(t => <span key={t} className="tag">{t}</span>)}</div></div>}
            {cvss && <div><p className="section-label">CVSS Vector</p><code className="cvss-vector">{cvss}</code></div>}
          </div>
          {!f.description && !(f.cwe || []).length && !(f.wstg || []).length && !(f.top10 || []).length && !cvss &&
            <div className="no-data">No additional classification metadata.</div>}
        </>}
        {tab === 'remediation' && (f.remediation ? <div className="remediation">{f.remediation}</div>
          : <div className="no-data">No remediation guidance available for this finding.</div>)}
      </div>
    </div>
  )
}

/* ── Sidebar severity group ───────────────────────── */
function SevGroup({ sev, items, selectedId, onSelect, triage, collapsed, toggle, rowRef }) {
  if (!items.length) return null
  const c = `var(--${sev})`
  const open = !collapsed
  return (
    <div className="severity-group">
      <div className="severity-group-header" style={{ color: c }} onClick={toggle}>
        <span className="dot" style={{ background: c }} />{LABELS[sev]}
        <span className="group-count">{items.length}</span>
        <span className="caret">{open ? '▾' : '▸'}</span>
      </div>
      {open && items.map((f) => {
        const st = triage[f.id] || 'open'
        return (
          <div key={f.id} ref={el => rowRef(f.id, el)} data-fid={f.id}
            className={`finding-row ${selectedId === f.id ? 'active' : ''} ${st === 'fp' ? 'dismissed' : ''}`}
            role="option" aria-selected={selectedId === f.id} onClick={() => onSelect(f)}>
            <div className="type">{f.type || f.title}
              {st === 'reviewed' && <I.check className="row-flag ok" width="13" height="13" />}
              {st === 'fp' && <I.xcircle className="row-flag bad" width="13" height="13" />}
            </div>
            <div className="url">{f.url}{f.parameter ? ` → ${f.parameter}` : ''}</div>
            <div className="row-meta">
              {f.tool && <span className="mini-tag tool">{f.tool}</span>}
              {f.cvss > 0 && <span className="mini-tag">CVSS {Number(f.cvss).toFixed(1)}</span>}
              {f.verified && <span className="mini-tag verified">verified</span>}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function Traffic({ entries }) {
  const [sel, setSel] = useState(null)
  const cur = entries.find(e => e.id === sel) || null
  return (
    <div className="traffic">
      <div className="traffic-table-wrap">
        <table className="traffic-table">
          <thead><tr>
            <th className="col-id">#</th><th className="col-method">Method</th><th className="col-url">URL</th>
            <th className="col-status">Status</th><th className="col-len">Length</th><th className="col-time">Time</th>
          </tr></thead>
          <tbody>
            {entries.map(e => (
              <tr key={e.id} className={sel === e.id ? 'active' : ''} onClick={() => setSel(e.id)}>
                <td className="col-id">{e.id}</td>
                <td className="col-method"><span className={`method ${e.method}`}>{e.method}</span></td>
                <td className="col-url" title={e.url}>{e.url}</td>
                <td className="col-status"><span className={`status-${String(e.status)[0]}`}>{e.status || '—'}</span></td>
                <td className="col-len">{e.length}</td>
                <td className="col-time">{e.duration_ms}ms</td>
              </tr>
            ))}
            {!entries.length && <tr><td colSpan={6} style={{ textAlign: 'center', padding: '28px', color: 'var(--ink-faint)', lineHeight: 1.6 }}>No HTTP traffic recorded.<br />Run the scan with <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>--capture</code> to record tool traffic (HTTP targets only).</td></tr>}
          </tbody>
        </table>
      </div>
      {cur && (
        <div className="traffic-detail">
          <div className="traffic-pane"><h4>Request</h4><Code text={cur.request} /></div>
          <div className="traffic-pane"><h4>Response</h4><Code text={cur.response} /></div>
        </div>
      )}
    </div>
  )
}

/* ── Root ─────────────────────────────────────────── */
export default function App() {
  const [findings, setFindings] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [status, setStatus] = useState('loading')
  const [target, setTarget] = useState('')
  const [pct, setPct] = useState(0)
  const [view, setView] = useState('findings')
  const [history, setHistory] = useState([])
  const [query, setQuery] = useState('')
  const [muted, setMuted] = useState({})
  const [collapsed, setCollapsed] = useState({})
  const [tab, setTab] = useState('request')
  const [hideDismissed, setHideDismissed] = useState(false)
  const [toast, setToast] = useState(null)
  const [showHelp, setShowHelp] = useState(false)
  const [triage, setTriage] = useState(() => { try { return JSON.parse(localStorage.getItem('vigil-triage') || '{}') } catch { return {} } })
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem('vigil-theme') || 'dark' } catch { return 'dark' } })

  const searchRef = useRef(null)
  const rowRefs = useRef({})
  const setRowRef = useCallback((id, el) => { if (el) rowRefs.current[id] = el; else delete rowRefs.current[id] }, [])

  useEffect(() => { document.documentElement.setAttribute('data-theme', theme); try { localStorage.setItem('vigil-theme', theme) } catch {} }, [theme])
  useEffect(() => { try { localStorage.setItem('vigil-triage', JSON.stringify(triage)) } catch {} }, [triage])

  const showToast = useCallback((msg) => { setToast(msg); clearTimeout(showToast._t); showToast._t = setTimeout(() => setToast(null), 1800) }, [])

  // Mirror triage so the FP sync reads the previous state without stale closures.
  const triageRef = useRef(triage)
  useEffect(() => { triageRef.current = triage }, [triage])

  // Persist a false-positive decision to the scanner's FP database so future
  // `vigil scan --fp-database` runs suppress it. Best-effort; UI state stands
  // regardless, but we surface a failure so the operator knows it didn't stick.
  const syncFP = useCallback((id, isFP) => {
    fetch('/api/fp', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, fp: isFP }),
    }).then(r => { if (!r.ok) showToast('Could not save to FP database') }).catch(() => showToast('FP database unreachable'))
  }, [showToast])

  const setTriageFor = useCallback((id, state) => {
    const prev = triageRef.current[id] || 'open'
    if (state === 'fp' && prev !== 'fp') syncFP(id, true)
    else if (prev === 'fp' && state !== 'fp') syncFP(id, false)
    setTriage(t => ({ ...t, [id]: state }))
  }, [syncFP])

  const load = useCallback(() => {
    fetch('/api/target').then(r => r.json()).then(d => { setTarget(d.target || ''); setStatus(d.status || 'running') }).catch(() => {})
    fetch('/api/findings').then(r => r.json()).then(f => { if (Array.isArray(f) && f.length) setFindings(f) }).catch(() => {})
    fetch('/api/history').then(r => r.json()).then(h => { if (Array.isArray(h)) setHistory(h.sort((a, b) => a.id - b.id)) }).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    const poll = setInterval(load, 3000)
    const es = new EventSource('/api/events')
    es.addEventListener('finding', e => { try { const f = JSON.parse(e.data)?.data; if (f) setFindings(prev => prev.some(p => p.id === f.id) ? prev : [...prev, f]) } catch {} })
    es.addEventListener('progress', e => { try { const p = JSON.parse(e.data)?.data; if (p) setPct(p.total > 0 ? Math.round(p.tested / p.total * 100) : 0) } catch {} })
    es.addEventListener('complete', () => { setStatus('complete'); load() })
    return () => { es.close(); clearInterval(poll) }
  }, [load])

  const q = query.trim().toLowerCase()
  const counts = {}; SEV.forEach(s => counts[s] = findings.filter(f => (f.severity || 'info').toLowerCase() === s).length)
  const total = findings.length
  const fpCount = findings.filter(f => triage[f.id] === 'fp').length

  // Visible, ordered findings (severity → CVSS desc) respecting search / mutes / dismissed.
  const visible = useMemo(() => {
    let list = findings.filter(f => {
      const s = (f.severity || 'info').toLowerCase()
      if (muted[s]) return false
      if (hideDismissed && triage[f.id] === 'fp') return false
      if (!q) return true
      return [f.type, f.title, f.url, f.parameter, f.tool, f.description].some(v => (v || '').toLowerCase().includes(q))
    })
    list.sort((a, b) => {
      const sa = SEV_RANK[(a.severity || 'info').toLowerCase()] ?? 9
      const sb = SEV_RANK[(b.severity || 'info').toLowerCase()] ?? 9
      if (sa !== sb) return sa - sb
      return (b.cvss || 0) - (a.cvss || 0)
    })
    return list
  }, [findings, muted, hideDismissed, triage, q])

  const grouped = {}; SEV.forEach(s => grouped[s] = [])
  visible.forEach(f => grouped[(f.severity || 'info').toLowerCase()].push(f))

  const selected = findings.find(f => f.id === selectedId) || null
  useEffect(() => { if (!selectedId && visible.length) setSelectedId(visible[0].id) }, [visible, selectedId])
  useEffect(() => { setTab('request') }, [selectedId])

  // Move selection by delta within the visible list, scrolling into view.
  const move = useCallback((delta) => {
    if (!visible.length) return
    const idx = visible.findIndex(f => f.id === selectedId)
    const next = idx < 0 ? 0 : Math.min(visible.length - 1, Math.max(0, idx + delta))
    const nf = visible[next]
    if (nf) { setSelectedId(nf.id); rowRefs.current[nf.id]?.scrollIntoView({ block: 'nearest' }) }
  }, [visible, selectedId])

  // Global keyboard shortcuts for fast daily triage.
  useEffect(() => {
    const onKey = (e) => {
      const typing = document.activeElement?.tagName === 'INPUT' || document.activeElement?.tagName === 'TEXTAREA'
      if (e.key === '/' && !typing) { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'Escape') { if (typing) { searchRef.current?.blur() } setQuery(q => q); setShowHelp(false); return }
      if (e.key === '?' && !typing) { setShowHelp(s => !s); return }
      if (typing) return
      if (view !== 'findings') return
      if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); move(1) }
      else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); move(-1) }
      else if (e.key >= '1' && e.key <= '4') { setTab(TAB_KEYS[+e.key - 1]) }
      else if (e.key === 't') { setTheme(t => t === 'dark' ? 'light' : 'dark') }
      else if (selected && (e.key === 'r')) { const st = triage[selected.id] === 'reviewed' ? 'open' : 'reviewed'; setTriageFor(selected.id, st); showToast(st === 'reviewed' ? 'Marked reviewed' : 'Reopened') }
      else if (selected && (e.key === 'f')) { const st = triage[selected.id] === 'fp' ? 'open' : 'fp'; setTriageFor(selected.id, st); showToast(st === 'fp' ? 'Marked false positive' : 'Restored') }
      else if (selected && (e.key === 'y')) { copy(selected.url); showToast('URL copied') }
      else if (selected && (e.key === 'c')) { copy(findingToMarkdown(selected)); showToast('Finding copied as Markdown') }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [move, view, selected, triage, setTriageFor, showToast])

  return (
    <div className="app">
      <div className="topbar">
        <div className="logo"><I.shield width="24" height="24" /><span>vigil</span></div>
        <div className="target-url"><I.target width="14" height="14" /><b>{target || 'No target'}</b></div>
        <div className="score-summary">
          {SEV.map(s => counts[s] > 0 && (
            <button key={s} className={`stat ${s} ${muted[s] ? 'dim' : ''}`} aria-pressed={!muted[s]}
              title={`${counts[s]} ${LABELS[s]} — click to ${muted[s] ? 'show' : 'hide'}`} onClick={() => setMuted(m => ({ ...m, [s]: !m[s] }))}>
              <span className="pill">{counts[s]}</span><span className="pill-label">{s}</span>
            </button>
          ))}
        </div>
        <div className="top-right">
          <div className="scan-status">
            <span className={`status-dot ${status === 'running' ? 'running' : status === 'loading' ? 'loading' : 'complete'}`} />
            <span className="status-text">{status === 'loading' ? 'connecting' : status}{status === 'running' && pct > 0 ? ` · ${pct}%` : ''}</span>
          </div>
          <button className="icon-btn" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts" onClick={() => setShowHelp(s => !s)}><I.keyboard width="16" height="16" /></button>
          <button className="icon-btn" title="Toggle theme (t)" aria-label="Toggle theme" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? <I.sun width="16" height="16" /> : <I.moon width="16" height="16" />}</button>
        </div>
        {status === 'running' && <div className="progress-bar"><div className="fill" style={{ width: `${pct}%` }} /></div>}
      </div>

      <div className="sidebar">
        <div className="view-switch">
          <button className={view === 'findings' ? 'active' : ''} onClick={() => setView('findings')}><I.bug width="15" height="15" /> Findings <span className="vs-count">{total}</span></button>
          <button className={view === 'traffic' ? 'active' : ''} onClick={() => setView('traffic')}><I.activity width="15" height="15" /> Traffic <span className="vs-count">{history.length}</span></button>
        </div>
        {view === 'findings' && <>
          <div className="search-wrap">
            <I.search width="15" height="15" />
            <input ref={searchRef} value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter findings…  ( / )" aria-label="Filter findings" />
          </div>
          {fpCount > 0 && (
            <label className="toolbar-toggle">
              <input type="checkbox" checked={hideDismissed} onChange={e => setHideDismissed(e.target.checked)} />
              Hide {fpCount} false positive{fpCount > 1 ? 's' : ''}
            </label>
          )}
          <div className="finding-list" role="listbox" aria-label="Findings">
            {SEV.map(s => !muted[s] && <SevGroup key={s} sev={s} items={grouped[s] || []} selectedId={selectedId} onSelect={f => setSelectedId(f.id)}
              triage={triage} collapsed={collapsed[s]} toggle={() => setCollapsed(c => ({ ...c, [s]: !c[s] }))} rowRef={setRowRef} />)}
            {!visible.length && <div className="sidebar-empty">{status === 'running' ? 'Scanning…' : q ? 'No findings match your filter' : 'No findings'}</div>}
          </div>
        </>}
        {view === 'traffic' && (
          <div className="finding-list" style={{ padding: '14px 16px', color: 'var(--ink-muted)', fontSize: 13, lineHeight: 1.6 }}>
            Request/response pairs for proxied tool traffic appear in the main panel. Enable recording by scanning with <code style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>--capture</code>.
          </div>
        )}
      </div>

      <div className="main">
        {view === 'findings'
          ? <Detail f={selected} tab={tab} setTab={setTab} triage={triage} setTriageFor={setTriageFor} onToast={showToast} />
          : <Traffic entries={history} />}
      </div>

      {toast && <div className="toast" role="status">{toast}</div>}

      {showHelp && (
        <div className="help-overlay" onClick={() => setShowHelp(false)}>
          <div className="help-card" onClick={e => e.stopPropagation()}>
            <h3><I.keyboard width="18" height="18" /> Keyboard shortcuts</h3>
            <dl>
              <div><dt><kbd>↑</kbd><kbd>↓</kbd> / <kbd>j</kbd><kbd>k</kbd></dt><dd>Move between findings</dd></div>
              <div><dt><kbd>1</kbd>–<kbd>4</kbd></dt><dd>Switch detail tabs</dd></div>
              <div><dt><kbd>/</kbd></dt><dd>Focus search</dd></div>
              <div><dt><kbd>r</kbd></dt><dd>Mark reviewed</dd></div>
              <div><dt><kbd>f</kbd></dt><dd>Mark false positive</dd></div>
              <div><dt><kbd>y</kbd></dt><dd>Copy URL</dd></div>
              <div><dt><kbd>c</kbd></dt><dd>Copy finding as Markdown</dd></div>
              <div><dt><kbd>t</kbd></dt><dd>Toggle theme</dd></div>
              <div><dt><kbd>Esc</kbd></dt><dd>Close / blur search</dd></div>
            </dl>
            <button className="copy-btn" onClick={() => setShowHelp(false)}>Close</button>
          </div>
        </div>
      )}
    </div>
  )
}
