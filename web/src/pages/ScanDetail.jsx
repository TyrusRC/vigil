import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { SEV, LABELS, SEV_RANK, sevOf, copy, findingToMarkdown } from '../util'
import { Detail, SevGroup, TAB_KEYS } from '../components/Finding'
import { StatusPill, Spinner } from '../components/ui'

const REPORT_FORMATS = ['json', 'sarif', 'html', 'markdown', 'csv']
const FRAMEWORKS = [{ id: 'pci-dss', name: 'PCI-DSS' }, { id: 'hipaa', name: 'HIPAA' }, { id: 'iso-27001', name: 'ISO 27001' }]

export default function ScanDetail({ id, go, toast }) {
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [query, setQuery] = useState('')
  const [muted, setMuted] = useState({})
  const [collapsed, setCollapsed] = useState({})
  const [tab, setTab] = useState('request')
  const [hideDismissed, setHideDismissed] = useState(false)
  const [mode, setMode] = useState('findings') // findings | compliance
  const [triage, setTriage] = useState(() => { try { return JSON.parse(localStorage.getItem('vigil-triage-' + id) || '{}') } catch { return {} } })

  const searchRef = useRef(null)
  const rowRefs = useRef({})
  const setRowRef = useCallback((fid, el) => { if (el) rowRefs.current[fid] = el; else delete rowRefs.current[fid] }, [])

  useEffect(() => { try { localStorage.setItem('vigil-triage-' + id, JSON.stringify(triage)) } catch {} }, [triage, id])

  const loadFindings = useCallback(() => {
    api.findings(id).then(f => { if (Array.isArray(f)) setFindings(f) }).catch(() => {})
  }, [id])
  const loadScan = useCallback(() => {
    api.getScan(id).then(setScan).catch(() => toast('Scan not found'))
  }, [id, toast])

  // Load + live stream. Poll scan status while running; SSE pushes findings.
  useEffect(() => {
    loadScan(); loadFindings()
    const es = new EventSource(api.eventsURL(id))
    es.addEventListener('finding', e => {
      try { const f = JSON.parse(e.data)?.finding; if (f) setFindings(prev => prev.some(p => p.id === f.id) ? prev : [...prev, f]) } catch {}
    })
    es.addEventListener('complete', () => { loadScan(); loadFindings() })
    es.addEventListener('error', () => { loadScan() })
    const poll = setInterval(() => { if (scanRef.current && (scanRef.current.status === 'running' || scanRef.current.status === 'queued')) loadScan() }, 3000)
    return () => { es.close(); clearInterval(poll) }
  }, [id, loadScan, loadFindings])

  // Mirror scan into a ref so the poll closure reads the latest status.
  const scanRef = useRef(scan)
  useEffect(() => { scanRef.current = scan }, [scan])

  // Persist a false-positive decision to the scanner's FP database. Local triage
  // stands regardless; a failure is surfaced so the operator knows.
  const syncFP = useCallback((fid, isFP) => {
    api.markFP(id, fid, isFP, '').catch(() => toast('Could not save to FP database'))
  }, [id, toast])

  const triageRef = useRef(triage)
  useEffect(() => { triageRef.current = triage }, [triage])
  const setTriageFor = useCallback((fid, state) => {
    const prev = triageRef.current[fid] || 'open'
    if (state === 'fp' && prev !== 'fp') syncFP(fid, true)
    else if (prev === 'fp' && state !== 'fp') syncFP(fid, false)
    setTriage(t => ({ ...t, [fid]: state }))
  }, [syncFP])

  const q = query.trim().toLowerCase()
  const counts = {}; SEV.forEach(s => counts[s] = findings.filter(f => sevOf(f) === s).length)
  const fpCount = findings.filter(f => triage[f.id] === 'fp').length

  const visible = useMemo(() => {
    let list = findings.filter(f => {
      const s = sevOf(f)
      if (muted[s]) return false
      if (hideDismissed && triage[f.id] === 'fp') return false
      if (!q) return true
      return [f.type, f.title, f.url, f.parameter, f.tool, f.description].some(v => (v || '').toLowerCase().includes(q))
    })
    list.sort((a, b) => {
      const sa = SEV_RANK[sevOf(a)] ?? 9, sb = SEV_RANK[sevOf(b)] ?? 9
      if (sa !== sb) return sa - sb
      return (b.cvss || 0) - (a.cvss || 0)
    })
    return list
  }, [findings, muted, hideDismissed, triage, q])

  const grouped = {}; SEV.forEach(s => grouped[s] = [])
  visible.forEach(f => grouped[sevOf(f)].push(f))

  const selected = findings.find(f => f.id === selectedId) || null
  useEffect(() => { if (!selectedId && visible.length) setSelectedId(visible[0].id) }, [visible, selectedId])
  useEffect(() => { setTab('request') }, [selectedId])

  const move = useCallback((delta) => {
    if (!visible.length) return
    const idx = visible.findIndex(f => f.id === selectedId)
    const next = idx < 0 ? 0 : Math.min(visible.length - 1, Math.max(0, idx + delta))
    const nf = visible[next]
    if (nf) { setSelectedId(nf.id); rowRefs.current[nf.id]?.scrollIntoView({ block: 'nearest' }) }
  }, [visible, selectedId])

  useEffect(() => {
    const onKey = (e) => {
      const typing = document.activeElement?.tagName === 'INPUT' || document.activeElement?.tagName === 'TEXTAREA'
      if (e.key === '/' && !typing) { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'Escape' && typing) { searchRef.current?.blur(); return }
      if (typing || mode !== 'findings') return
      if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); move(1) }
      else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); move(-1) }
      else if (e.key >= '1' && e.key <= '4') { setTab(TAB_KEYS[+e.key - 1]) }
      else if (selected && e.key === 'r') { const st = triage[selected.id] === 'reviewed' ? 'open' : 'reviewed'; setTriageFor(selected.id, st); toast(st === 'reviewed' ? 'Marked reviewed' : 'Reopened') }
      else if (selected && e.key === 'f') { const st = triage[selected.id] === 'fp' ? 'open' : 'fp'; setTriageFor(selected.id, st); toast(st === 'fp' ? 'Marked false positive' : 'Restored') }
      else if (selected && e.key === 'y') { copy(selected.url); toast('URL copied') }
      else if (selected && e.key === 'c') { copy(findingToMarkdown(selected)); toast('Finding copied as Markdown') }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [move, mode, selected, triage, setTriageFor, toast])

  if (!scan) return <Spinner label="Loading scan…" />
  const running = scan.status === 'running' || scan.status === 'queued'

  return (
    <div className="page scan-detail">
      <div className="sd-head">
        <button className="btn ghost tiny back" onClick={() => go('#/scans')}>← Scans</button>
        <span className="mono sd-target">{scan.target}</span>
        <StatusPill status={scan.status} />
        {running && <span className="sd-live">streaming · {findings.length} found</span>}
        <div className="sd-sev">
          {SEV.map(s => counts[s] > 0 && (
            <button key={s} className={`stat ${s} ${muted[s] ? 'dim' : ''}`} aria-pressed={!muted[s]}
              title={`${counts[s]} ${LABELS[s]} — click to ${muted[s] ? 'show' : 'hide'}`} onClick={() => setMuted(m => ({ ...m, [s]: !m[s] }))}>
              <span className="pill">{counts[s]}</span><span className="pill-label">{s}</span>
            </button>
          ))}
        </div>
        <div className="sd-actions">
          <div className="report-menu">
            <span className="rm-label"><I.download width="14" height="14" /> Report</span>
            {REPORT_FORMATS.map(fmt => (
              <a key={fmt} className={`rm-fmt ${scan.status !== 'completed' ? 'disabled' : ''}`}
                href={scan.status === 'completed' ? api.reportURL(id, fmt) : undefined}
                target="_blank" rel="noreferrer" title={scan.status === 'completed' ? `Download ${fmt}` : 'Scan not completed'}>{fmt}</a>
            ))}
          </div>
        </div>
      </div>

      {running && <div className="sd-progress"><div className="indeterminate" /></div>}

      <div className="sd-tabs">
        <button className={mode === 'findings' ? 'active' : ''} onClick={() => setMode('findings')}><I.bug width="14" height="14" /> Findings <span className="vs-count">{findings.length}</span></button>
        <button className={mode === 'compliance' ? 'active' : ''} onClick={() => setMode('compliance')} disabled={scan.status !== 'completed'}><I.shieldCheck width="14" height="14" /> Compliance</button>
      </div>

      {mode === 'findings' ? (
        <div className="sd-body">
          <aside className="sd-list">
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
              {!visible.length && <div className="sidebar-empty">{running ? 'Scanning…' : q ? 'No findings match your filter' : scan.status === 'failed' ? (scan.error || 'Scan failed') : 'No findings'}</div>}
            </div>
          </aside>
          <div className="sd-detail">
            <Detail f={selected} tab={tab} setTab={setTab} triage={triage} setTriageFor={setTriageFor} onToast={toast} />
          </div>
        </div>
      ) : (
        <Compliance id={id} toast={toast} />
      )}
    </div>
  )
}

function Compliance({ id, toast }) {
  const [fw, setFw] = useState('pci-dss')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true); setData(null)
    api.compliance(id, fw).then(setData).catch(ex => toast(ex.message || 'Could not assess')).finally(() => setLoading(false))
  }, [id, fw, toast])

  return (
    <div className="sd-compliance">
      <div className="fw-switch">
        {FRAMEWORKS.map(f => <button key={f.id} className={fw === f.id ? 'active' : ''} onClick={() => setFw(f.id)}>{f.name}</button>)}
      </div>
      {loading ? <Spinner label="Assessing…" /> : data ? (
        <pre className="code-block compliance-json">{JSON.stringify(data, null, 2)}</pre>
      ) : <div className="no-data">No assessment available.</div>}
    </div>
  )
}
