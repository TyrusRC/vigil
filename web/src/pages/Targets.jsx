import React, { useEffect, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { ago } from '../util'
import { DataTable, Modal, Field, Spinner } from '../components/ui'

function AddTargetModal({ onClose, onAdded, toast }) {
  const [url, setUrl] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    if (!url.trim()) { setErr('Enter a target URL.'); return }
    setBusy(true); setErr('')
    try { await api.createTarget(url.trim(), label.trim()); toast('Target added'); onAdded() }
    catch (ex) { setErr(ex.message || 'Could not add target.'); setBusy(false) }
  }

  return (
    <Modal title="Add target" onClose={onClose}>
      <form onSubmit={submit}>
        <Field label="URL" hint="http:// or https://">
          <input autoFocus value={url} onChange={e => setUrl(e.target.value)} placeholder="https://app.example.com" />
        </Field>
        <Field label="Label" hint="Optional — a name to recognise this target by.">
          <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Staging app" />
        </Field>
        {err && <div className="form-error"><I.alert width="15" height="15" /> {err}</div>}
        <div className="modal-actions">
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding…' : 'Add target'}</button>
        </div>
      </form>
    </Modal>
  )
}

export default function Targets({ go, toast }) {
  const [targets, setTargets] = useState(null)
  const [showAdd, setShowAdd] = useState(false)

  const load = () => api.listTargets().then(t => setTargets(t || [])).catch(() => setTargets([]))
  useEffect(() => { load() }, [])

  const scan = async (e, t) => {
    e.stopPropagation()
    try { const job = await api.scanTarget(t.id); toast('Scan started'); go('#/scans/' + job.id) }
    catch (ex) { toast(ex.message || 'Could not start scan') }
  }
  const remove = async (e, t) => {
    e.stopPropagation()
    if (!window.confirm(`Remove target ${t.url}? Scans already run are kept.`)) return
    try { await api.deleteTarget(t.id); toast('Target removed'); load() }
    catch (ex) { toast(ex.message || 'Could not remove') }
  }

  if (targets === null) return <Spinner label="Loading targets…" />

  return (
    <div className="page targets">
      <div className="page-head">
        <h1>Targets</h1>
        <button className="btn primary" onClick={() => setShowAdd(true)}><I.plus width="15" height="15" /> Add target</button>
      </div>

      <DataTable
        rowKey={t => t.id}
        onRowClick={t => t.last_scan_id && go('#/scans/' + t.last_scan_id)}
        columns={[
          { key: 'url', label: 'Target', render: t => <span className="mono cell-target">{t.url}</span> },
          { key: 'label', label: 'Label', width: '180px', render: t => t.label || <span className="dim">—</span> },
          { key: 'last', label: 'Last scan', width: '130px', render: t => t.last_scan_id ? <span className="link-ish">open ↗</span> : <span className="dim">never</span> },
          { key: 'added', label: 'Added', width: '110px', align: 'right', render: t => ago(t.created_at) },
          {
            key: 'act', label: '', width: '150px', align: 'right', render: t => (
              <span className="row-actions">
                <button className="btn tiny primary" onClick={e => scan(e, t)}><I.play width="12" height="12" /> Scan</button>
                <button className="btn tiny ghost danger" onClick={e => remove(e, t)} aria-label="Remove target"><I.trash width="13" height="13" /></button>
              </span>
            )
          },
        ]}
        rows={targets}
        empty="No saved targets. Add one to re-scan it on demand."
      />

      {showAdd && <AddTargetModal onClose={() => setShowAdd(false)} toast={toast} onAdded={() => { setShowAdd(false); load() }} />}
    </div>
  )
}
