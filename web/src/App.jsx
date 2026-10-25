import React, { useEffect, useState, useCallback, useRef } from 'react'
import { listScans, createScan, getReport, subscribeScan } from './api.js'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

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
      <button className="copy-btn" onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
    </div>
  )
}

function FindingDetail({ finding }) {
  const [tab, setTab] = useState('request')

  if (!finding) return (
    <div className="empty-state">
      <div className="icon">&#128269;</div>
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
            <span><span className="label">URL:</span> {f.url}</span>
            {f.parameter && <span><span className="label">Param:</span> {f.parameter}</span>}
            {f.tool && <span><span className="label">Tool:</span> {f.tool}</span>}
            {f.verified && <span className="verified">&#10003; Verified</span>}
          </div>
        </div>
        <Badge severity={sev} />
      </div>

      <div className="tabs">
        <div className={`tab ${tab === 'request' ? 'active' : ''}`} onClick={() => setTab('request')}>Request</div>
        <div className={`tab ${tab === 'response' ? 'active' : ''}`} onClick={() => setTab('response')}>Response</div>
        <div className={`tab ${tab === 'details' ? 'active' : ''}`} onClick={() => setTab('details')}>Details</div>
        <div className={`tab ${tab === 'remediation' ? 'active' : ''}`} onClick={() => setTab('remediation')}>Remediation</div>
      </div>

      <div className="tab-content">
        {tab === 'request' && (
          <>
            {f.request ? (
              <CodeBlock content={f.request} highlights={highlights} />
            ) : (
              <p style={{ color: 'var(--ink-muted)' }}>No HTTP request captured for this finding.</p>
            )}
            <CurlBlock curl={f.request} />
          </>
        )}

        {tab === 'response' && (
          <>
            {f.response ? (
              <CodeBlock content={f.response} highlights={[f.evidence, ...(f.cwe || [])]} />
            ) : f.evidence ? (
              <CodeBlock content={f.evidence} highlights={highlights} />
            ) : (
              <p style={{ color: 'var(--ink-muted)' }}>No HTTP response captured.</p>
            )}
          </>
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
            {f.confidence && (
              <p style={{ marginTop: 12, fontSize: 13, color: 'var(--ink-muted)' }}>
                Confidence: {f.confidence}
              </p>
            )}
          </>
        )}

        {tab === 'remediation' && (
          <div className="remediation">
            {f.remediation || 'No remediation guidance available for this finding.'}
          </div>
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
      <div
        className="severity-group-header"
        style={{ color: colors[severity] }}
        onClick={() => setCollapsed(!collapsed)}
      >
        <span className="dot" style={{ background: colors[severity] }} />
        {SEV_LABELS[severity]}
        <span className="group-count" style={{ color: 'var(--sidebar-text)' }}>{findings.length}</span>
      </div>
      {!collapsed && findings.map((f, i) => (
        <div
          key={f.id || i}
          className={`finding-row ${selected?.id === f.id ? 'active' : ''}`}
          onClick={() => onSelect(f)}
        >
          <div className="type">{f.type || f.title}</div>
          <div className="url">{f.url}</div>
        </div>
      ))}
    </div>
  )
}

function SummaryBar({ findings, scanInfo }) {
  const counts = {}
  for (const s of SEV_ORDER) counts[s] = 0
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase()
    counts[s] = (counts[s] || 0) + 1
  }
  const colors = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--low)', info: 'var(--info)' }
  return (
    <div className="summary-bar">
      <div className="stat">
        <span className="n">{findings.length}</span>
        <span className="label">Total</span>
      </div>
      <div className="divider" />
      {SEV_ORDER.map(s => counts[s] > 0 && (
        <div key={s} className="stat" style={{ color: colors[s] }}>
          <span className="n">{counts[s]}</span>
          <span className="label">{s}</span>
        </div>
      ))}
      {scanInfo && (
        <span className="scan-info">{scanInfo}</span>
      )}
    </div>
  )
}

export default function App() {
  const [scans, setScans] = useState([])
  const [currentScan, setCurrentScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [status, setStatus] = useState('idle')
  const [progress, setProgress] = useState({ phase: '', tested: 0, total: 0, pct: 0 })
  const [target, setTarget] = useState('')
  const [scanning, setScanning] = useState(false)
  const [scanInfo, setScanInfo] = useState('')
  const unsubRef = useRef(null)

  useEffect(() => {
    listScans().then(data => {
      setScans(data || [])
      const active = (data || []).find(s => s.status === 'running') || (data || [])[0]
      if (active) loadScan(active)
    }).catch(() => {})
  }, [])

  const loadScan = useCallback(async (scan) => {
    setCurrentScan(scan)
    setTarget(scan.target || '')
    setStatus(scan.status || 'idle')

    if (scan.status === 'running') {
      setScanning(true)
      subscribeToScan(scan.id)
    } else {
      setScanning(false)
    }

    try {
      const report = await getReport(scan.id)
      const f = report?.scan_result?.findings || []
      setFindings(f)
      if (f.length > 0) setSelected(f[0])
      const dur = report?.scan_result?.duration
      setScanInfo(dur ? `Duration: ${(dur / 1e9).toFixed(0)}s` : '')
    } catch {
      setFindings([])
    }
  }, [])

  const subscribeToScan = (id) => {
    if (unsubRef.current) unsubRef.current()
    const unsub = subscribeScan(id, {
      onFinding: (f) => {
        setFindings(prev => {
          const exists = prev.some(p => p.id === f.id)
          if (exists) return prev
          return [...prev, f]
        })
      },
      onProgress: (p) => {
        setProgress({
          phase: p.phase || '',
          tested: p.tested || 0,
          total: p.total || 0,
          pct: p.total > 0 ? Math.round((p.tested / p.total) * 100) : 0,
        })
      },
      onDone: () => {
        setStatus('completed')
        setScanning(false)
      },
    })
    unsubRef.current = unsub
  }

  const startScan = async () => {
    if (!target.trim() || scanning) return
    setScanning(true)
    setFindings([])
    setSelected(null)
    setStatus('running')
    setProgress({ phase: 'starting', tested: 0, total: 0, pct: 0 })
    try {
      const scan = await createScan({ target: target.trim() })
      setCurrentScan(scan)
      subscribeToScan(scan.id)
    } catch (e) {
      setStatus('failed')
      setScanning(false)
      setScanInfo(`Error: ${e.message}`)
    }
  }

  const grouped = {}
  for (const s of SEV_ORDER) grouped[s] = []
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase()
    if (!grouped[s]) grouped[s] = []
    grouped[s].push(f)
  }

  const pct = progress.pct || 0

  return (
    <>
      <div className="topbar">
        <div className="logo">vigil</div>
        <div className="target">{target || 'No target'}</div>
        <span className={`scan-status ${status}`}>{status}</span>
      </div>

      {scanning && (
        <div className="progress-bar">
          <div className="fill" style={{ width: `${pct}%` }} />
        </div>
      )}

      <SummaryBar findings={findings} scanInfo={scanInfo} />

      <div className="layout">
        <div className="sidebar">
          <div className="new-scan">
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              placeholder="https://example.com"
              onKeyDown={e => e.key === 'Enter' && startScan()}
            />
            <button onClick={startScan} disabled={scanning || !target.trim()}>
              {scanning ? 'Scanning...' : 'Scan'}
            </button>
          </div>

          <div className="sidebar-header">
            <h2>Findings</h2>
            <span className="count">{findings.length}</span>
          </div>

          {SEV_ORDER.map(s => (
            <SeverityGroup
              key={s}
              severity={s}
              findings={grouped[s]}
              selected={selected}
              onSelect={setSelected}
            />
          ))}
        </div>

        <div className="main">
          <FindingDetail finding={selected} />
        </div>
      </div>
    </>
  )
}
