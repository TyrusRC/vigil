import React, { useEffect, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { ago } from '../util'
import { DataTable, StatusPill, Modal, Field, Spinner } from '../components/ui'
import { ScanConfigForm } from '../components/ScanConfigForm'

function NewScanModal({ onClose, onCreated, toast, profiles, detectors }) {
  const [target, setTarget] = useState('')
  const [cfg, setCfg] = useState({})
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    if (!target.trim()) { setErr('Enter a target URL.'); return }
    setBusy(true); setErr('')
    try {
      // Omit an untouched config so the server applies the saved Settings
      // defaults — same behaviour as scanning a saved target.
      const body = { target: target.trim() }
      if (Object.keys(cfg).length) body.config = cfg
      const job = await api.createScan(body)
      toast('Scan started')
      onCreated(job)
    } catch (ex) {
      setErr(ex.message || 'Could not start scan.')
      setBusy(false)
    }
  }

  return (
    <Modal title="New scan" onClose={onClose} wide>
      <form onSubmit={submit}>
        <Field label="Target URL" hint="http:// or https:// — the scan starts from here.">
          <input autoFocus value={target} onChange={e => setTarget(e.target.value)} placeholder="https://app.example.com" />
        </Field>
        <ScanConfigForm value={cfg} onChange={setCfg} profiles={profiles} detectors={detectors} />
        {err && <div className="form-error"><I.alert width="15" height="15" /> {err}</div>}
        <div className="modal-actions">
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Starting…' : <><I.play width="14" height="14" /> Start scan</>}</button>
        </div>
      </form>
    </Modal>
  )
}

export default function Scans({ go, toast }) {
  const [jobs, setJobs] = useState(null)
  const [showNew, setShowNew] = useState(false)
  const [profiles, setProfiles] = useState([])
  const [detectors, setDetectors] = useState([])

  const load = () => api.listScans().then(j => setJobs(Array.isArray(j) ? j.slice().reverse() : [])).catch(() => setJobs([]))

  useEffect(() => {
    load()
    api.profiles().then(setProfiles).catch(() => {})
    api.configDefaults().then(d => setDetectors(d.detectors || [])).catch(() => {})
    const poll = setInterval(load, 4000)
    return () => clearInterval(poll)
  }, [])

  const cancel = async (e, id) => {
    e.stopPropagation()
    try { await api.cancelScan(id); toast('Scan cancelled'); load() }
    catch (ex) { toast(ex.message || 'Could not cancel') }
  }

  if (jobs === null) return <Spinner label="Loading scans…" />

  return (
    <div className="page scans">
      <div className="page-head">
        <h1>Scans</h1>
        <button className="btn primary" onClick={() => setShowNew(true)}><I.plus width="15" height="15" /> New scan</button>
      </div>

      <DataTable
        rowKey={j => j.id}
        onRowClick={j => go('#/scans/' + j.id)}
        columns={[
          { key: 'target', label: 'Target', render: j => <span className="mono cell-target">{j.target}</span> },
          { key: 'profile', label: 'Profile', width: '110px', render: j => j.profile || 'normal' },
          { key: 'status', label: 'Status', width: '130px', render: j => <StatusPill status={j.status} /> },
          { key: 'findings', label: 'Findings', width: '90px', align: 'right', render: j => j.summary ? j.summary.TotalFindings : (j.status === 'running' ? '…' : '—') },
          { key: 'when', label: 'Started', width: '100px', align: 'right', render: j => ago(j.created_at) },
          {
            key: 'act', label: '', width: '92px', align: 'right', render: j =>
              j.status === 'running' || j.status === 'queued'
                ? <button className="btn tiny ghost" onClick={e => cancel(e, j.id)}>Cancel</button>
                : null
          },
        ]}
        rows={jobs}
        empty="No scans yet. Click “New scan” to run one."
      />

      {showNew && (
        <NewScanModal
          onClose={() => setShowNew(false)} toast={toast} profiles={profiles} detectors={detectors}
          onCreated={(job) => { setShowNew(false); load(); go('#/scans/' + job.id) }}
        />
      )}
    </div>
  )
}
