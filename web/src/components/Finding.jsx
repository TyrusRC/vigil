import React from 'react'
import { I } from '../icons'
import { SEV, LABELS, SEV_RANK, sevOf, cvssBand, copy, findingToMarkdown, Code, CurlCopy } from '../util'

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

/* One finding row — shared by the severity and endpoint groupings.
   primary: what the bold line shows — 'type' (default) or 'param' (used inside a
   same-type group, where the type is already in the header and the parameter is
   what distinguishes the rows). hideUrl drops the redundant URL when the group
   header already states it. */
function FindingRow({ f, selectedId, onSelect, triage, rowRef, showSev, primary = 'type', hideUrl }) {
  const st = triage[f.id] || 'open'
  const sev = sevOf(f)
  const label = primary === 'param' ? (f.parameter || f.type || f.title) : (f.type || f.title)
  return (
    <div ref={el => rowRef(f.id, el)} data-fid={f.id}
      className={`finding-row ${selectedId === f.id ? 'active' : ''} ${st === 'fp' ? 'dismissed' : ''}`}
      role="option" aria-selected={selectedId === f.id} onClick={() => onSelect(f)}>
      <div className="type">
        {showSev && <span className="row-sev-dot" style={{ background: `var(--${sev})` }} title={LABELS[sev]} />}
        {label}
        {st === 'reviewed' && <I.check className="row-flag ok" width="13" height="13" />}
        {st === 'fp' && <I.xcircle className="row-flag bad" width="13" height="13" />}
      </div>
      {!hideUrl && <div className="url">{f.url}{f.parameter ? ` → ${f.parameter}` : ''}</div>}
      <div className="row-meta">
        {f.tool && <span className="mini-tag tool">{f.tool}</span>}
        {f.cvss > 0 && <span className="mini-tag">CVSS {Number(f.cvss).toFixed(1)}</span>}
        {f.verified && <span className="mini-tag verified">verified</span>}
      </div>
    </div>
  )
}

/* Compact severity spread for a group header: one colored pip per severity
   present, carrying its count, so a mixed group's makeup is visible unexpanded. */
function SevSpread({ counts }) {
  return (
    <span className="eg-sevs">
      {SEV.filter(s => counts[s]).map(s => (
        <span key={s} className="sev-pip" style={{ background: `var(--${s})` }} title={`${counts[s]} ${LABELS[s]}`}>{counts[s]}</span>
      ))}
    </span>
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

/* Collapsible endpoint group. A group is one of:
   - 'param': many detectors on one (URL, parameter) — the reflected-param pile;
   - 'type':  one finding type repeated across many parameters of one URL — e.g.
     a "Missing Security Header" per header, collapsed into a single cluster so
     they stop fragmenting the list;
   - 'single': a lone finding that shares neither axis with another.
   Rows show whichever axis is NOT in the header (type inside a param group, the
   parameter inside a type group), and the header carries the full severity
   spread rather than a single top dot. */
export function EndpointGroup({ group, selectedId, onSelect, triage, collapsed, toggle, rowRef }) {
  const { kind, parameter, typeLabel, path, url, items, sevCounts } = group
  const open = !collapsed
  const openCount = items.filter(f => (triage[f.id] || 'open') !== 'fp').length
  const header = kind === 'type'
    ? <span className="eg-param"><span className="eg-typelabel">{typeLabel}</span></span>
    : parameter
      ? <span className="eg-param">param <span className="mono">{parameter}</span></span>
      : <span className="eg-pagelevel">page-level</span>
  return (
    <div className="endpoint-group">
      <div className="endpoint-group-header" onClick={toggle}>
        <SevSpread counts={sevCounts} />
        {header}
        <span className="eg-url mono" title={url}>{path}</span>
        <span className="group-count" title={`${openCount} open of ${items.length}`}>{items.length}</span>
        <span className="caret">{open ? '▾' : '▸'}</span>
      </div>
      {open && items.map((f) => (
        <FindingRow key={f.id} f={f} selectedId={selectedId} onSelect={onSelect} triage={triage}
          rowRef={rowRef} showSev primary={kind === 'type' ? 'param' : 'type'} hideUrl />
      ))}
    </div>
  )
}

// urlPath strips scheme+host so the distinguishing path/query tail (e.g. the
// matrix-param ";.css" that separates two page-level groups) stays visible
// instead of being truncated off the right edge of the full URL.
function urlPath(u) {
  try { const x = new URL(u); return (x.pathname + x.search) || '/' } catch { return u }
}

// finalize computes the worst severity and the per-severity counts for a group.
function finalize(g) {
  const sevCounts = {}
  let topSev = sevOf(g.items[0])
  for (const f of g.items) {
    const s = sevOf(f)
    sevCounts[s] = (sevCounts[s] || 0) + 1
    if ((SEV_RANK[s] ?? 9) < (SEV_RANK[topSev] ?? 9)) topSev = s
  }
  return { ...g, topSev, sevCounts, path: urlPath(g.url) }
}

/* Build endpoint groups from a flat, pre-sorted finding list, in two passes:
   1) cluster by (URL, parameter) — multi-item clusters become 'param' groups;
   2) the leftover singletons re-cluster by (URL, type) — a repeated type (the
      security-header case) becomes one 'type' group; a truly lone finding stays
      a 'single'. Groups rank by worst severity, then size. This stops the
      grouping from trading one noise pattern for a parade of 1-item groups. */
export function groupByEndpoint(list) {
  const byParam = new Map()
  for (const f of list) {
    const key = `${f.url}\u0000${f.parameter || ''}`
    let g = byParam.get(key)
    if (!g) { g = { kind: 'param', url: f.url, parameter: f.parameter || '', items: [] }; byParam.set(key, g) }
    g.items.push(f)
  }

  const out = []
  const singletonsByType = new Map()
  for (const g of byParam.values()) {
    if (g.items.length > 1) { out.push(finalize(g)); continue }
    const f = g.items[0]
    const tkey = `${f.url}\u0000${(f.type || f.title || '').toLowerCase()}`
    let t = singletonsByType.get(tkey)
    if (!t) { t = { url: f.url, typeLabel: f.type || f.title, items: [] }; singletonsByType.set(tkey, t) }
    t.items.push(f)
  }
  for (const t of singletonsByType.values()) {
    if (t.items.length > 1) out.push(finalize({ kind: 'type', url: t.url, typeLabel: t.typeLabel, items: t.items }))
    else out.push(finalize({ kind: 'single', url: t.url, parameter: t.items[0].parameter || '', items: t.items }))
  }

  return out.sort((a, b) => {
    const sa = SEV_RANK[a.topSev] ?? 9, sb = SEV_RANK[b.topSev] ?? 9
    if (sa !== sb) return sa - sb
    return b.items.length - a.items.length
  })
}

export { TAB_KEYS }
