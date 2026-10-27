import React, { useState } from 'react'
import { Field } from './ui'

// list helpers: UI edits comma/space lists as plain strings; convert on commit.
const toList = (s) => (s || '').split(/[,\s]+/).map(x => x.trim()).filter(Boolean)
const fromList = (a) => (a || []).join(', ')

/* ScanConfigForm is a controlled editor for a ScanConfig. It calls onChange with
   a fresh config object on every edit. Transport, scope and detector sections
   are collapsible so the common case (pick a profile, go) stays uncluttered. */
export function ScanConfigForm({ value, onChange, profiles, detectors }) {
  const cfg = value || {}
  const [openAdv, setOpenAdv] = useState(false)
  const [openDet, setOpenDet] = useState(false)
  const [detFilter, setDetFilter] = useState('')

  const set = (patch) => onChange({ ...cfg, ...patch })
  const setDetector = (name, on) => {
    const d = { ...(cfg.detectors || {}) }
    if (on === null) delete d[name]
    else d[name] = on
    onChange({ ...cfg, detectors: d })
  }

  const num = (v) => { const n = Number(v); return isNaN(n) || n <= 0 ? undefined : n }
  const shownDetectors = (detectors || []).filter(n => !detFilter || n.includes(detFilter.toLowerCase()))

  return (
    <div className="config-form">
      <Field label="Profile" hint="Baseline intensity; individual settings below override it.">
        <select value={cfg.profile || ''} onChange={e => set({ profile: e.target.value || undefined })}>
          <option value="">normal (default)</option>
          {(profiles || []).map(p => <option key={p.name} value={p.name}>{p.name} — {p.description}</option>)}
        </select>
      </Field>

      <button type="button" className={`disclosure ${openAdv ? 'open' : ''}`} onClick={() => setOpenAdv(o => !o)}>
        <span className="caret">{openAdv ? '▾' : '▸'}</span> Transport &amp; scope
      </button>
      {openAdv && (
        <div className="config-grid">
          <Field label="Rate (req/s)" hint="0 = unlimited">
            <input type="number" min="0" value={cfg.rate || ''} onChange={e => set({ rate: num(e.target.value) })} placeholder="0" />
          </Field>
          <Field label="Concurrency">
            <input type="number" min="0" value={cfg.concurrency || ''} onChange={e => set({ concurrency: num(e.target.value) })} placeholder="auto" />
          </Field>
          <Field label="Timeout (s)">
            <input type="number" min="0" value={cfg.timeout_seconds || ''} onChange={e => set({ timeout_seconds: num(e.target.value) })} placeholder="default" />
          </Field>
          <Field label="Method">
            <input value={cfg.method || ''} onChange={e => set({ method: e.target.value || undefined })} placeholder="GET" />
          </Field>
          <Field label="Cookie">
            <input value={cfg.cookie || ''} onChange={e => set({ cookie: e.target.value || undefined })} placeholder="session=…" />
          </Field>
          <Field label="User-Agent">
            <input value={cfg.user_agent || ''} onChange={e => set({ user_agent: e.target.value || undefined })} placeholder="default" />
          </Field>
          <Field label="In-scope hosts" hint="comma separated">
            <input value={fromList(cfg.scope_hosts)} onChange={e => set({ scope_hosts: toList(e.target.value) })} placeholder="app.example.com" />
          </Field>
          <Field label="Include paths" hint="comma separated">
            <input value={fromList(cfg.include_path)} onChange={e => set({ include_path: toList(e.target.value) })} placeholder="/api/" />
          </Field>
          <Field label="Exclude paths" hint="comma separated">
            <input value={fromList(cfg.exclude_path)} onChange={e => set({ exclude_path: toList(e.target.value) })} placeholder="/logout" />
          </Field>
          <div className="config-checks">
            <label className="check"><input type="checkbox" checked={!!cfg.insecure} onChange={e => set({ insecure: e.target.checked || undefined })} /> Skip TLS verification</label>
            <label className="check"><input type="checkbox" checked={!!cfg.spa_crawl} onChange={e => set({ spa_crawl: e.target.checked || undefined })} /> SPA crawl (needs Chrome)</label>
            <label className="check"><input type="checkbox" checked={!!cfg.submit_forms} onChange={e => set({ submit_forms: e.target.checked || undefined })} /> Submit forms while crawling</label>
          </div>
        </div>
      )}

      {detectors && detectors.length > 0 && (
        <>
          <button type="button" className={`disclosure ${openDet ? 'open' : ''}`} onClick={() => setOpenDet(o => !o)}>
            <span className="caret">{openDet ? '▾' : '▸'}</span> Detectors
            {cfg.detectors && Object.keys(cfg.detectors).length > 0 && <span className="disc-badge">{Object.keys(cfg.detectors).length} set</span>}
          </button>
          {openDet && (
            <div className="detector-panel">
              <input className="det-filter" value={detFilter} onChange={e => setDetFilter(e.target.value)} placeholder={`Filter ${detectors.length} detectors…`} />
              <p className="field-hint">Leave a detector untouched to follow the profile. Explicitly enable or disable to override.</p>
              <div className="detector-list">
                {shownDetectors.map(name => {
                  const state = cfg.detectors && name in cfg.detectors ? (cfg.detectors[name] ? 'on' : 'off') : 'auto'
                  return (
                    <div key={name} className="det-row">
                      <span className="det-name">{name}</span>
                      <div className="tri">
                        <button type="button" className={state === 'off' ? 'sel bad' : ''} onClick={() => setDetector(name, false)}>off</button>
                        <button type="button" className={state === 'auto' ? 'sel' : ''} onClick={() => setDetector(name, null)}>auto</button>
                        <button type="button" className={state === 'on' ? 'sel ok' : ''} onClick={() => setDetector(name, true)}>on</button>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export { toList, fromList }
