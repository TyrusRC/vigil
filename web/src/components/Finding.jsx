import React from 'react'
import { I } from '../icons'
import { LABELS, sevOf, cvssBand, copy, findingToMarkdown, Code, CurlCopy } from '../util'

const TAB_KEYS = ['request', 'response', 'details', 'remediation']

/* Finding detail panel — evidence tabs, CVSS, classification, triage chips. */
export function Detail({ f, tab, setTab, triage, setTriageFor, onToast }) {
  if (!f) return (
    <div className="empty-state">
      <I.bug width="56" height="56" />
      <p>Select a finding to inspect evidence and remediation</p>
      <p className="hint-line"><kbd>↑</kbd><kbd>↓</kbd> navigate · <kbd>/</kbd> search · <kbd>1</kbd>–<kbd>4</kbd> tabs</p>
    </div>
  )

  const sev = sevOf(f)
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

export { TAB_KEYS }
