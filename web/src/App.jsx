import React, { useEffect, useState, useCallback, useRef } from 'react'
import { listScans, createScan, getReport, subscribeScan } from './api.js'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

// SVG Icons
const ShieldIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
)

const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
    <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
  </svg>
)

const CheckIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="#16a34a" strokeWidth="2.5" strokeLinecap="round"><path d="M20 6 9 17l-5-5"/></svg>
)

const CopyIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" width="14" height="14">
    <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
)

function Badge({ severity }) {
  return <span className={`badge ${severity}`}>{SEV_LABELS[severity] || severity}</span>
}

function highlightText(text, markers) {
  if (!text || !markers || markers.length === 0) return text
  let result = text
  for (const m of markers) {
    if (m && m.length > 2 && result.includes(m)) {
      result = result.split(m).join(`<mark>${m}</mark>`)
    }
  }
  return result
}

function CodeBlock({ content, highlights = [] }) {
  const html = highlightText(content || '', highlights)
  return <pre className="code-block" dangerouslySetInnerHTML={{ __html: html }} />
}

function CurlBlock({ curl }) {
  const [copied, setCopied] = useState(false)
  if (!curl) return null
  const copy = () => {
    navigator.clipboard.writeText(curl).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="curl-block">
      <code>{curl}</code>
      <button className="copy-btn" onClick={copy}>
        {copied ? '✓' : <CopyIcon />} {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

function FindingDetail({ finding }) {
  const [tab, setTab] = useState('request')
  if (!finding) return (
    <div className="empty-state">
      <SearchIcon />
      <p>Select a finding to view details</p>
    </div>
  )
  const f = finding
  const sev = (f.severity || 'info').toLowerCase()
  const highlights = []
  if (f.parameter) highlights.push(f.parameter)

  return (
    <div className="detail-card">
      <div className="detail-header">
        <div className="title-block">
          <h2>{f.type || f.title}</h2>
          <div className="detail-meta">
            <span><span className="label">URL</span> {f.url}</span>
            {f.parameter && <span><span className="label">Param</span> {f.parameter}</span>}
            {f.tool && <span><span className="label">Tool</span> {f.tool}</span>}
            {f.verified && <span className="verified"><CheckIcon /> Verified</span>}
          </div>
        </div>
        <Badge severity={sev} />
      </div>
      <div className="tabs">
        {['request', 'response', 'details', 'remediation'].map(t => (
          <div key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </div>
        ))}
      </div>
      <div className="tab-content">
        {tab === 'request' && (
          <>
            {f.request ? <CodeBlock content={f.request} highlights={highlights} /> :
              <p style={{ color: 'var(--ink-muted)' }}>No request captured.</p>}
            <CurlBlock curl={f.request} />
          </>
        )}
        {tab === 'response' && (
          f.response ? <CodeBlock content={f.response} highlights={[f.evidence, ...(f.cwe || [])]} /> :
          f.evidence ? <CodeBlock content={f.evidence} highlights={highlights} /> :
          <p style={{ color: 'var(--ink-muted)' }}>No response captured.</p>
        )}
        {tab === 'details' && (
          <>
            {f.description && <p className="remediation">{f.description}</p>}
            <div className="tags" style={{ marginTop: 16 }}>
              {(f.cwe || []).map(c => <span key={c} className="tag">{c}</span>)}
              {(f.wstg || []).map(w => <span key={w} className="tag">{w}</span>)}
              {(f.top10 || []).map(t => <span key={t} className="tag">OWASP {t}</span>)}
              {f.cvss_vector && <span className="tag">CVSS: {f.cvss_vector}</span>}
            </div>
          </>
        )}
        {tab === 'remediation' && (
          <div className="remediation">{f.remediation || 'No remediation guidance available.'}</div>
        )}
      </div>
    </div>
  )
}

function SeverityGroup({ severity, findings, selected, onSelect }) {
  const [collapsed, setCollapsed] = useState(false)
  if (findings.length === 0) return null
  const colors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' }
  return (
    <div className="severity-group">
      <div className="severity-group-header" style={{ color: colors[severity] }} onClick={() => setCollapsed(!collapsed)}>
        <span className="dot" style={{ background: colors[severity] }} />
        {SEV_LABELS[severity]}
        <span className="group-count">{findings.length}</span>
      </div>
      {!collapsed && findings.map((f, i) => (
        <div key={f.id || i} className={`finding-row ${selected?.id === f.id ? 'active' : ''}`} onClick={() => onSelect(f)}>
          <div className="type">{f.type || f.title}</div>
          <div className="url">{f.url}</div>
        </div>
      ))}
    </div>
  )
}

export default function App() {
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [status, setStatus] = useState('running')
  const [target, setTarget] = useState('')
  const [progress, setProgress] = useState({ pct: 0 })

  // On mount: fetch target info and connect SSE
  useEffect(() => {
    fetch('/api/target').then(r => r.json()).then(d => {
      setTarget(d.target || '')
      setStatus(d.status || 'running')
    }).catch(() => {})

    fetch('/api/findings').then(r => r.json()).then(f => {
      if (Array.isArray(f) && f.length > 0) {
        setFindings(f)
        setSelected(f[0])
      }
    }).catch(() => {})

    // SSE for real-time findings
    const es = new EventSource('/api/events')
    es.addEventListener('finding', (e) => {
      try {
        const ev = JSON.parse(e.data)
        const f = ev.data
        if (f) {
          setFindings(prev => {
            if (prev.some(p => p.id === f.id)) return prev
            return [...prev, f]
          })
        }
      } catch {}
    })
    es.addEventListener('progress', (e) => {
      try {
        const ev = JSON.parse(e.data)
        const p = ev.data
        if (p) setProgress({ pct: p.total > 0 ? Math.round((p.tested / p.total) * 100) : 0 })
      } catch {}
    })
    es.addEventListener('complete', () => {
      setStatus('complete')
      // Reload full findings list
      fetch('/api/findings').then(r => r.json()).then(f => {
        if (Array.isArray(f) && f.length > 0) setFindings(f)
      }).catch(() => {})
    })
    return () => es.close()
  }, [])

  const grouped = {}
  for (const s of SEV_ORDER) grouped[s] = []
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase()
    if (!grouped[s]) grouped[s] = []
    grouped[s].push(f)
  }

  const counts = {}
  for (const s of SEV_ORDER) counts[s] = (grouped[s] || []).length

  return (
    <div className="app">
      <div className="topbar">
        <div className="logo">
          <ShieldIcon />
          <span>vigil</span>
        </div>
        <div className="target-url">{target}</div>
        <div className="summary-chips">
          {SEV_ORDER.map(s => counts[s] > 0 && <span key={s} className={`chip ${s}`}>{counts[s]}</span>)}
        </div>
        <div className="scan-status">
          <span className={`status-dot ${status === 'running' ? 'running' : 'complete'}`} />
          <span className="status-text">{status}</span>
        </div>
        {status === 'running' && (
          <div className="progress-bar" style={{ width: '100%' }}><div className="fill" style={{ width: `${progress.pct}%` }} /></div>
        )}
      </div>

      <div className="sidebar">
        {SEV_ORDER.map(s => (
          <SeverityGroup key={s} severity={s} findings={grouped[s]} selected={selected} onSelect={setSelected} />
        ))}
        {findings.length === 0 && (
          <div style={{ padding: '40px 16px', textAlign: 'center', color: 'var(--sidebar-text)', fontSize: 13 }}>
            {status === 'running' ? 'Scanning...' : 'No findings'}
          </div>
        )}
      </div>

      <div className="main">
        <FindingDetail finding={selected} />
      </div>
    </div>
  )
}
