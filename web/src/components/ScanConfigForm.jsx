import React, { useState } from 'react'
import { Field } from './ui'

// list helpers: UI edits comma/space lists as plain strings; convert on commit.
const toList = (s) => (s || '').split(/[,\s]+/).map(x => x.trim()).filter(Boolean)
const fromList = (a) => (a || []).join(', ')

// header-map helpers: UI edits a map as "Name: value" lines; convert on commit.
// Empty → undefined so the field is omitted (profile/default wins).
const toHeaders = (s) => {
  const m = {}
  for (const line of (s || '').split('\n')) {
    const i = line.indexOf(':')
    if (i > 0) { const k = line.slice(0, i).trim(); if (k) m[k] = line.slice(i + 1).trim() }
  }
  return Object.keys(m).length ? m : undefined
}
const fromHeaders = (m) => Object.entries(m || {}).map(([k, v]) => `${k}: ${v}`).join('\n')

// Tri — a three-way control for a *bool knob: auto (follow profile) / on / off.
function Tri({ label, hint, value, onChange }) {
  const v = value === true ? 'on' : value === false ? 'off' : 'auto'
  return (
    <Field label={label} hint={hint}>
      <select value={v} onChange={e => onChange(e.target.value === 'on' ? true : e.target.value === 'off' ? false : undefined)}>
        <option value="auto">auto (profile)</option>
        <option value="on">on</option>
        <option value="off">off</option>
      </select>
    </Field>
  )
}

/* ScanConfigForm is a controlled editor for a ScanConfig. It calls onChange with
   a fresh config object on every edit. Each section is collapsible so the common
   case (pick a profile, go) stays uncluttered, while authenticated, access-control
   (IDOR), import and tuning knobs are one click away — the full scan surface the
   REST API and CLI accept. */
export function ScanConfigForm({ value, onChange, profiles, detectors }) {
  const cfg = value || {}
  const [openAdv, setOpenAdv] = useState(false)
  const [openAuth, setOpenAuth] = useState(false)
  const [openMore, setOpenMore] = useState(false)
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
            <label className="check"><input type="checkbox" checked={!!cfg.no_scope} onChange={e => set({ no_scope: e.target.checked || undefined })} /> Disable scope (test every host)</label>
            <label className="check"><input type="checkbox" checked={!!cfg.no_default_excludes} onChange={e => set({ no_default_excludes: e.target.checked || undefined })} /> Drop default path excludes</label>
          </div>
        </div>
      )}

      <button type="button" className={`disclosure ${openAuth ? 'open' : ''}`} onClick={() => setOpenAuth(o => !o)}>
        <span className="caret">{openAuth ? '▾' : '▸'}</span> Authentication &amp; access control
      </button>
      {openAuth && (
        <div className="config-grid">
          <Field label="Login URL" hint="Form-login page; vigil authenticates before scanning.">
            <input value={cfg.login_url || ''} onChange={e => set({ login_url: e.target.value || undefined })} placeholder="https://app.example.com/login" />
          </Field>
          <Field label="Login sequence (LSR)" hint="Path to a recorded login sequence file.">
            <input value={cfg.lsr_path || ''} onChange={e => set({ lsr_path: e.target.value || undefined })} placeholder="/path/to/login.lsr" />
          </Field>
          <div className="config-subhead">Two-identity access-control (IDOR)</div>
          <Field label="IDOR target URL" hint="Resource both identities request; a shared body flags broken access control.">
            <input value={cfg.idor_url || ''} onChange={e => set({ idor_url: e.target.value || undefined })} placeholder="https://app.example.com/api/orders/1001" />
          </Field>
          <Field label="Identity A cookie">
            <input value={cfg.auth_a_cookie || ''} onChange={e => set({ auth_a_cookie: e.target.value || undefined })} placeholder="session=userA…" />
          </Field>
          <Field label="Identity B cookie">
            <input value={cfg.auth_b_cookie || ''} onChange={e => set({ auth_b_cookie: e.target.value || undefined })} placeholder="session=userB…" />
          </Field>
          <Field label="Identity A headers" hint="one per line — Name: value">
            <textarea rows="2" value={fromHeaders(cfg.auth_a_headers)} onChange={e => set({ auth_a_headers: toHeaders(e.target.value) })} placeholder="Authorization: Bearer tokenA" />
          </Field>
          <Field label="Identity B headers" hint="one per line — Name: value">
            <textarea rows="2" value={fromHeaders(cfg.auth_b_headers)} onChange={e => set({ auth_b_headers: toHeaders(e.target.value) })} placeholder="Authorization: Bearer tokenB" />
          </Field>
        </div>
      )}

      <button type="button" className={`disclosure ${openMore ? 'open' : ''}`} onClick={() => setOpenMore(o => !o)}>
        <span className="caret">{openMore ? '▾' : '▸'}</span> Advanced
      </button>
      {openMore && (
        <div className="config-grid">
          <div className="config-subhead">Intensity</div>
          <Field label="Max payloads / param">
            <input type="number" min="0" value={cfg.max_payloads_per_param || ''} onChange={e => set({ max_payloads_per_param: num(e.target.value) })} placeholder="profile" />
          </Field>
          <Field label="Max params">
            <input type="number" min="0" value={cfg.max_params || ''} onChange={e => set({ max_params: num(e.target.value) })} placeholder="profile" />
          </Field>
          <Field label="Param concurrency">
            <input type="number" min="0" value={cfg.param_concurrency || ''} onChange={e => set({ param_concurrency: num(e.target.value) })} placeholder="profile" />
          </Field>
          <Tri label="WAF-bypass payloads" value={cfg.include_waf_bypass} onChange={v => set({ include_waf_bypass: v })} />
          <Tri label="Time-based SQLi" value={cfg.time_based_sqli} onChange={v => set({ time_based_sqli: v })} />

          <div className="config-subhead">Crawl &amp; discovery</div>
          <Field label="Crawl depth">
            <input type="number" min="0" value={cfg.crawl_depth || ''} onChange={e => set({ crawl_depth: num(e.target.value) })} placeholder="default" />
          </Field>
          <Field label="Max pages">
            <input type="number" min="0" value={cfg.crawl_max_pages || ''} onChange={e => set({ crawl_max_pages: num(e.target.value) })} placeholder="default" />
          </Field>
          <Field label="Chrome path" hint="override headless browser binary">
            <input value={cfg.chrome_path || ''} onChange={e => set({ chrome_path: e.target.value || undefined })} placeholder="auto-detect" />
          </Field>
          <div className="config-checks">
            <label className="check"><input type="checkbox" checked={!!cfg.state_crawl} onChange={e => set({ state_crawl: e.target.checked || undefined })} /> State-aware crawl</label>
          </div>

          <div className="config-subhead">Import &amp; templates</div>
          <Field label="API spec URL" hint="OpenAPI / Swagger to seed endpoints">
            <input value={cfg.api_spec || ''} onChange={e => set({ api_spec: e.target.value || undefined })} placeholder="https://app.example.com/openapi.json" />
          </Field>
          <Field label="Registration URL" hint="sign-up page for account-creation flows">
            <input value={cfg.registration_url || ''} onChange={e => set({ registration_url: e.target.value || undefined })} placeholder="https://app.example.com/signup" />
          </Field>
          <Field label="Template paths" hint="comma separated — enables template scan">
            <input value={fromList(cfg.templates)} onChange={e => set({ templates: toList(e.target.value) })} placeholder="/path/tpl.yaml" />
          </Field>
          <Field label="Template tags" hint="comma separated">
            <input value={fromList(cfg.template_tags)} onChange={e => set({ template_tags: toList(e.target.value) })} placeholder="cve, exposure" />
          </Field>

          <div className="config-subhead">Focus</div>
          <Field label="Only tests" hint="comma separated detector names">
            <input value={fromList(cfg.only_tests)} onChange={e => set({ only_tests: toList(e.target.value) })} placeholder="sqli, xss" />
          </Field>
          <Field label="Only params" hint="comma separated parameter names">
            <input value={fromList(cfg.only_params)} onChange={e => set({ only_params: toList(e.target.value) })} placeholder="id, user" />
          </Field>

          <div className="config-subhead">Custom request</div>
          <Field label="Request body data">
            <input value={cfg.data || ''} onChange={e => set({ data: e.target.value || undefined })} placeholder="a=1&b=2" />
          </Field>
          <Field label="Extra headers" hint="one per line — Name: value">
            <textarea rows="2" value={fromHeaders(cfg.headers)} onChange={e => set({ headers: toHeaders(e.target.value) })} placeholder="X-API-Key: …" />
          </Field>

          <div className="config-subhead">Data sources</div>
          <Field label="NVD API key" hint="raises CVE enrichment rate limit">
            <input value={cfg.nvd_api_key || ''} onChange={e => set({ nvd_api_key: e.target.value || undefined })} placeholder="optional" />
          </Field>
          <Field label="IAST callback addr" hint="host:port for the IAST sensor">
            <input value={cfg.iast_addr || ''} onChange={e => set({ iast_addr: e.target.value || undefined })} placeholder="127.0.0.1:9999" />
          </Field>
          <div className="config-checks">
            <label className="check"><input type="checkbox" checked={!!cfg.iast} onChange={e => set({ iast: e.target.checked || undefined })} /> Enable IAST sensor</label>
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

export { toList, fromList, toHeaders, fromHeaders }
