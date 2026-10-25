import React, { useEffect, useState } from 'react'

const SEV = ['critical', 'high', 'medium', 'low', 'info']
const LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

const Shield = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
const Search = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
const Copy = () => <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function highlight(text, marks) {
  if (!text) return ''
  let h = esc(text)
  for (const m of (marks||[])) {
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

function CurlCopy({ request, url }) {
  const [ok, set] = useState(false)
  const line = (request||'').split('\n')[0]||''
  const m = line.match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)/)
  const method = m?m[1]:'GET', u = m?m[2]:(url||'')
  const cmd = method==='GET' ? `curl -k '${u}'` : `curl -k -X ${method} '${u}'`
  return (
    <div className="curl-block">
      <code>{cmd}</code>
      <button className="copy-btn" onClick={() => { navigator.clipboard.writeText(cmd); set(true); setTimeout(()=>set(false),1500) }}>
        {ok ? '✓ Copied' : <><Copy/> Copy</>}
      </button>
    </div>
  )
}

function Detail({ f }) {
  const [tab, setTab] = useState('request')
  if (!f) return <div className="empty-state"><Search/><p>Select a finding to view details</p></div>

  const sev = (f.severity||'info').toLowerCase()
  const marks = [f.parameter, f.evidence].filter(Boolean)
  const cvss = f.cvss_vector || ''
  const cvssScore = f.cvss || 0

  return (
    <div className="detail-card">
      {/* Header */}
      <div className="detail-header">
        <div className="title-block">
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:8}}>
            <span className={`badge ${sev}`}>{LABELS[sev]}</span>
            <h2 style={{margin:0}}>{f.type || f.title}</h2>
          </div>
          <div className="detail-meta">
            <span><b>URL</b> {f.url}</span>
            {f.parameter && <span><b>Parameter</b> {f.parameter}</span>}
            {f.tool && <span><b>Tool</b> {f.tool}</span>}
            {f.verified && <span className="verified">✓ Verified</span>}
          </div>
          {/* CVSS prominently displayed */}
          {cvss && (
            <div className="cvss-bar" style={{marginTop:10}}>
              <span className="cvss-score">{cvssScore > 0 ? cvssScore.toFixed(1) : ''}</span>
              <code className="cvss-vector">{cvss}</code>
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        {['request','response','details','remediation'].map(t =>
          <div key={t} className={`tab ${tab===t?'active':''}`} onClick={()=>setTab(t)}>
            {t[0].toUpperCase()+t.slice(1)}
          </div>
        )}
      </div>

      {/* Content */}
      <div className="tab-content">
        {tab === 'request' && <>
          {f.request
            ? <Code text={f.request} marks={marks} />
            : <div className="no-data">No raw HTTP request captured for this finding.
                {f.evidence && <><br/><br/><b>Evidence:</b> {f.evidence}</>}
              </div>
          }
          <CurlCopy request={f.request} url={f.url} />
        </>}

        {tab === 'response' && <>
          {f.response
            ? <Code text={f.response} marks={marks} />
            : f.evidence
              ? <div><p className="section-label">Evidence</p><Code text={f.evidence} marks={[f.parameter]} /></div>
              : <div className="no-data">No HTTP response captured.</div>
          }
        </>}

        {tab === 'details' && <>
          {f.description && <p style={{marginBottom:16,lineHeight:1.6}}>{f.description}</p>}

          <div className="detail-grid">
            {(f.cwe||[]).length > 0 && <div><p className="section-label">CWE</p><div className="tags">{f.cwe.map(c => <span key={c} className="tag">{c}</span>)}</div></div>}
            {(f.wstg||[]).length > 0 && <div><p className="section-label">WSTG</p><div className="tags">{f.wstg.map(w => <span key={w} className="tag">{w}</span>)}</div></div>}
            {(f.top10||[]).length > 0 && <div><p className="section-label">OWASP Top 10</p><div className="tags">{f.top10.map(t => <span key={t} className="tag">{t}</span>)}</div></div>}
            {cvss && <div><p className="section-label">CVSS 3.1 Vector</p><code className="cvss-full">{cvss}</code></div>}
            {f.confidence && <div><p className="section-label">Confidence</p><span className="tag">{f.confidence}</span></div>}
          </div>
        </>}

        {tab === 'remediation' && <div className="remediation">{f.remediation || 'No remediation guidance available for this finding.'}</div>}
      </div>
    </div>
  )
}

function SevGroup({ sev, items, selected, onSelect }) {
  const [open, setOpen] = useState(true)
  if (!items.length) return null
  const c = `var(--${sev})`
  return (
    <div className="severity-group">
      <div className="severity-group-header" style={{color:c}} onClick={()=>setOpen(!open)}>
        <span className="dot" style={{background:c}}/>{LABELS[sev]}<span className="group-count">{items.length}</span>
        <span style={{marginLeft:'auto',fontSize:10,opacity:0.5}}>{open?'▼':'▶'}</span>
      </div>
      {open && items.map((f,i) =>
        <div key={f.id||i} className={`finding-row ${selected?.id===f.id?'active':''}`} onClick={()=>onSelect(f)}>
          <div className="type">{f.type||f.title}</div>
          <div className="url">{f.url}{f.parameter ? ` → ${f.parameter}` : ''}</div>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [status, setStatus] = useState('loading')
  const [target, setTarget] = useState('')
  const [pct, setPct] = useState(0)

  const load = () => {
    fetch('/api/target').then(r=>r.json()).then(d => {
      setTarget(d.target||''); setStatus(d.status||'running')
    }).catch(()=>{})
    fetch('/api/findings').then(r=>r.json()).then(f => {
      if (Array.isArray(f) && f.length) { setFindings(f); if (!selected) setSelected(f[0]) }
    }).catch(()=>{})
  }

  useEffect(() => {
    load()
    // Poll every 3s to keep findings fresh (survives page refresh)
    const poll = setInterval(load, 3000)

    // SSE for instant updates
    const es = new EventSource('/api/events')
    es.addEventListener('finding', e => {
      try {
        const f = JSON.parse(e.data)?.data
        if (f) setFindings(prev => prev.some(p=>p.id===f.id) ? prev : [...prev, f])
      } catch {}
    })
    es.addEventListener('progress', e => {
      try {
        const p = JSON.parse(e.data)?.data
        if (p) setPct(p.total>0 ? Math.round(p.tested/p.total*100) : 0)
      } catch {}
    })
    es.addEventListener('complete', () => { setStatus('complete'); load() })
    return () => { es.close(); clearInterval(poll) }
  }, [])

  // Group by severity
  const grouped = {}; SEV.forEach(s => grouped[s] = [])
  findings.forEach(f => { const s=(f.severity||'info').toLowerCase(); (grouped[s]||(grouped[s]=[])).push(f) })
  const counts = {}; SEV.forEach(s => counts[s] = (grouped[s]||[]).length)
  const total = findings.length

  return (
    <div className="app">
      <div className="topbar">
        <div className="logo"><Shield/><span>vigil</span></div>
        <div className="target-url">{target || 'No target'}</div>
        <div className="summary-chips">
          {total > 0 && <span className="chip-total">{total}</span>}
          {SEV.map(s => counts[s]>0 && <span key={s} className={`chip ${s}`}>{counts[s]}</span>)}
        </div>
        <div className="scan-status">
          <span className={`status-dot ${status==='running'?'running':'complete'}`}/>
          <span className="status-text">{status==='loading'?'connecting':status}</span>
        </div>
        {status==='running' && <div className="progress-bar" style={{width:'100%'}}><div className="fill" style={{width:`${pct}%`}}/></div>}
      </div>

      <div className="sidebar">
        {SEV.map(s => <SevGroup key={s} sev={s} items={grouped[s]||[]} selected={selected} onSelect={setSelected}/>)}
        {!total && <div style={{padding:'40px 16px',textAlign:'center',color:'var(--sidebar-text)',fontSize:13}}>
          {status==='running'?'Scanning...':'No findings'}
        </div>}
      </div>

      <div className="main"><Detail f={selected}/></div>
    </div>
  )
}
