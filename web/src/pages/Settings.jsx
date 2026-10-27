import React, { useEffect, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { Spinner } from '../components/ui'
import { ScanConfigForm } from '../components/ScanConfigForm'

export default function Settings({ toast }) {
  const [cfg, setCfg] = useState(null)
  const [profiles, setProfiles] = useState([])
  const [detectors, setDetectors] = useState([])
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    api.getSettings().then(c => setCfg(c || {})).catch(() => setCfg({}))
    api.profiles().then(setProfiles).catch(() => {})
    api.configDefaults().then(d => setDetectors(d.detectors || [])).catch(() => {})
  }, [])

  const save = async () => {
    setSaving(true); setErr('')
    try { await api.putSettings(cfg); toast('Default scan settings saved') }
    catch (ex) { setErr(ex.message || 'Could not save settings.') }
    finally { setSaving(false) }
  }
  const reset = async () => {
    if (!window.confirm('Reset default scan settings to empty (profile-driven)?')) return
    setCfg({})
    try { await api.putSettings({}); toast('Settings reset') } catch (ex) { toast(ex.message || 'Could not reset') }
  }

  if (cfg === null) return <Spinner label="Loading settings…" />

  return (
    <div className="page settings">
      <div className="page-head">
        <h1>Settings</h1>
        <div className="row-actions">
          <button className="btn ghost" onClick={reset}>Reset</button>
          <button className="btn primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : <><I.check width="14" height="14" /> Save defaults</>}</button>
        </div>
      </div>
      <p className="page-intro">These settings become the default configuration applied to a new scan when its request doesn’t specify one — including scans launched from a saved target. A per-scan configuration still overrides them.</p>

      <div className="settings-panel">
        <ScanConfigForm value={cfg} onChange={setCfg} profiles={profiles} detectors={detectors} />
        {err && <div className="form-error"><I.alert width="15" height="15" /> {err}</div>}
      </div>
    </div>
  )
}
