import React, { useEffect, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { SEV, ago } from '../util'
import { SeverityDonut, StatCard, DataTable, StatusPill, Spinner } from '../components/ui'

const SUM_KEY = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

function aggregate(jobs) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const j of jobs) {
    if (!j.summary) continue
    for (const s of SEV) c[s] += j.summary[SUM_KEY[s]] || 0
  }
  return c
}

export default function Dashboard({ go }) {
  const [jobs, setJobs] = useState(null)
  const [tools, setTools] = useState([])

  useEffect(() => {
    let live = true
    const load = () => {
      api.listScans().then(j => { if (live) setJobs(Array.isArray(j) ? j.slice().reverse() : []) }).catch(() => live && setJobs([]))
    }
    load()
    api.tools().then(t => live && setTools(t || [])).catch(() => {})
    const poll = setInterval(load, 4000)
    return () => { live = false; clearInterval(poll) }
  }, [])

  if (jobs === null) return <Spinner label="Loading dashboard…" />

  const counts = aggregate(jobs)
  const running = jobs.filter(j => j.status === 'running' || j.status === 'queued').length
  const totalFindings = SEV.reduce((n, s) => n + counts[s], 0)
  const completed = jobs.filter(j => j.status === 'completed').length
  const available = tools.filter(t => t.available).length

  return (
    <div className="page dashboard">
      <section className="dash-hero">
        <div className="hero-donut">
          <SeverityDonut counts={counts} />
        </div>
        <div className="hero-stats">
          <StatCard label="Open findings" value={totalFindings} icon="bug" tone={counts.critical ? 'critical' : counts.high ? 'high' : 'ok'} />
          <StatCard label="Scans run" value={jobs.length} icon="activity" />
          <StatCard label="Completed" value={completed} icon="check" />
          <StatCard label="In progress" value={running} icon="clock" tone={running ? 'run' : undefined} />
        </div>
      </section>

      <section className="dash-block">
        <div className="block-head">
          <h2>Recent scans</h2>
          <button className="btn ghost" onClick={() => go('#/scans')}>View all</button>
        </div>
        <DataTable
          rowKey={j => j.id}
          onRowClick={j => go('#/scans/' + j.id)}
          columns={[
            { key: 'target', label: 'Target', render: j => <span className="mono cell-target">{j.target}</span> },
            { key: 'profile', label: 'Profile', width: '110px', render: j => j.profile || '—' },
            { key: 'status', label: 'Status', width: '130px', render: j => <StatusPill status={j.status} /> },
            { key: 'findings', label: 'Findings', width: '90px', align: 'right', render: j => j.summary ? j.summary.TotalFindings : '—' },
            { key: 'when', label: 'Started', width: '110px', align: 'right', render: j => ago(j.created_at) },
          ]}
          rows={jobs.slice(0, 8)}
          empty="No scans yet. Start one from the Scans page."
        />
      </section>

      <section className="dash-block">
        <div className="block-head"><h2>Scanner tools</h2><span className="block-sub">{available} of {tools.length} available</span></div>
        <div className="tool-grid">
          {tools.map(t => (
            <div key={t.name} className={`tool-chip ${t.available ? 'on' : 'off'}`}>
              <span className="tc-dot" />
              <span className="tc-name">{t.name}</span>
              {t.available && t.version && <span className="tc-ver">{t.version}</span>}
            </div>
          ))}
          {!tools.length && <span className="block-sub">No external tools reported.</span>}
        </div>
      </section>
    </div>
  )
}
