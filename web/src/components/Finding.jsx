import React from 'react'
import { I } from '../icons'
import { LABELS, SEV_RANK, sevOf, cvssBand, copy, findingToMarkdown, Code, CurlCopy } from '../util'

// Evidence is now one side-by-side pane (request | response, Burp-style) rather
// than two separate tabs, so a red-teamer reads the exchange without flipping.
const TAB_KEYS = ['evidence', 'details', 'remediation']

/* Finding detail panel — evidence (request|response side by side), CVSS, classification, triage chips. */
export function Detail({ f, tab, setTab, triage, setTriageFor, onToast }) {
  if (!f) return (
    <div className="empty-state">
      <I.bug width="56" height="56" />
      <p>Select a finding to inspect evidence and remediation</p>
      <p className="hint-line"><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>/</kbd> search · <kbd>1</kbd>–<kbd>3</kbd> tabs</p>
    </div>
  )

  const sev = sevOf(f)
  const marks = [f.parameter, f.evidence].filter(Boolean)
  const cvss = f.cvss_vector || ''
  const score = f.cvss || 0
  const band = cvssBand(score)
  const state = triage[f.id] || 'open'
  const labels = { evidence: 'Evidence', details: 'Details', remediation: 'Remediation' }
  const hasReq = !!f.request
  const hasResp = !!(f.response || f.evidence)

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
            {k === 'evidence' && (hasReq || hasResp) && <span className="tab-dot" />}
          </div>
        ))}
      </div>

      <div className="tab-content">
        {tab === 'evidence' && (
          (hasReq || hasResp) ? (
            <div className="evidence-split">
              <div className="evidence-pane">
                <div className="evidence-pane-head">
                  <span className="section-label">Request</span>
                  {hasReq && <button className="pane-copy" title="Copy request" onClick={() => { copy(f.request); onToast('Request copied') }}><I.copy width="12" height="12" /></button>}
                </div>
                {hasReq ? <Code text={f.request} marks={marks} />
                  : <div className="no-data">No raw HTTP request captured for this finding.</div>}
                {hasReq && <CurlCopy request={f.request} url={f.url} onCopy={onToast} />}
              </div>
              <div className="evidence-pane">
                <div className="evidence-pane-head">
                  <span className="section-label">Response</span>
                  {f.response && <button className="pane-copy" title="Copy response" onClick={() => { copy(f.response); onToast('Response copied') }}><I.copy width="12" height="12" /></button>}
                </div>
                {f.response ? <Code text={f.response} marks={marks} />
                  : f.evidence ? <><p className="evidence-sub">Evidence excerpt</p><Code text={f.evidence} marks={[f.parameter]} /></>
                    : <div className="no-data">No HTTP response captured.</div>}
              </div>
            </div>
          ) : (
            <div className="no-data">No raw HTTP traffic captured for this finding.{f.evidence && <><br /><br /><b>Evidence:</b> {f.evidence}</>}
              <br /><br />Tip: run the scan with <code>--capture</code> to record full request/response traffic.</div>
          )
        )}
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

/* One finding row — shared by the severity and endpoint groupings. */
function FindingRow({ f, selectedId, onSelect, triage, rowRef, showSev }) {
  const st = triage[f.id] || 'open'
  const sev = sevOf(f)
  return (
    <div ref={el => rowRef(f.id, el)} data-fid={f.id}
      className={`finding-row ${selectedId === f.id ? 'active' : ''} ${st === 'fp' ? 'dismissed' : ''}`}
      role="option" aria-selected={selectedId === f.id} onClick={() => onSelect(f)}>
      <div className="type">
        {showSev && <span className="row-sev-dot" style={{ background: `var(--${sev})` }} title={LABELS[sev]} />}
        {f.type || f.title}
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
}

/* Collapsible severity group in the findings sidebar. */
export function SevGroup({ sev, items, selectedId, onSelect, triage, collapsed, toggle, rowRef }) {
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
      {open && items.map((f) => (
        <FindingRow key={f.id} f={f} selectedId={selectedId} onSelect={onSelect} triage={triage} rowRef={rowRef} />
      ))}
    </div>
  )
}

/* Collapsible endpoint+parameter group — collapses the many detectors that
   fire on one (URL, parameter) into a single expandable cluster, so a reflected
   param that lights up seven detectors reads as one target, not seven rows. */
export function EndpointGroup({ group, selectedId, onSelect, triage, collapsed, toggle, rowRef }) {
  const { url, parameter, items, topSev } = group
  const open = !collapsed
  const c = `var(--${topSev})`
  const openCount = items.filter(f => (triage[f.id] || 'open') !== 'fp').length
  return (
    <div className="endpoint-group">
      <div className="endpoint-group-header" onClick={toggle}>
        <span className="dot" style={{ background: c }} />
        <span className="eg-param">{parameter ? <>param <span className="mono">{parameter}</span></> : <span className="eg-pagelevel">page-level</span>}</span>
        <span className="eg-url mono" title={url}>{url}</span>
        <span className="group-count" title={`${openCount} open of ${items.length}`}>{items.length}</span>
        <span className="caret">{open ? '▾' : '▸'}</span>
      </div>
      {open && items.map((f) => (
        <FindingRow key={f.id} f={f} selectedId={selectedId} onSelect={onSelect} triage={triage} rowRef={rowRef} showSev />
      ))}
    </div>
  )
}

/* Build endpoint groups from a flat, pre-sorted finding list. Groups are keyed
   by (url, parameter), ranked by their worst severity then by size, and each
   group's findings keep the incoming severity order. */
export function groupByEndpoint(list) {
  const map = new Map()
  for (const f of list) {
    const key = `${f.url}\u0000${f.parameter || ''}`
    let g = map.get(key)
    if (!g) { g = { url: f.url, parameter: f.parameter || '', items: [], topSev: sevOf(f) }; map.set(key, g) }
    g.items.push(f)
    if ((SEV_RANK[sevOf(f)] ?? 9) < (SEV_RANK[g.topSev] ?? 9)) g.topSev = sevOf(f)
  }
  return [...map.values()].sort((a, b) => {
    const sa = SEV_RANK[a.topSev] ?? 9, sb = SEV_RANK[b.topSev] ?? 9
    if (sa !== sb) return sa - sb
    return b.items.length - a.items.length
  })
}

export { TAB_KEYS }
