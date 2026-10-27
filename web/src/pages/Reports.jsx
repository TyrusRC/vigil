import React, { useEffect, useState } from 'react'
import { api } from '../api'
import { I } from '../icons'
import { ago } from '../util'
import { DataTable, Spinner, PageEmpty } from '../components/ui'

const FORMATS = [
  { id: 'json', label: 'JSON' },
  { id: 'sarif', label: 'SARIF' },
  { id: 'html', label: 'HTML' },
  { id: 'markdown', label: 'Markdown' },
  { id: 'csv', label: 'CSV' },
]

export default function Reports({ go, toast }) {
  const [jobs, setJobs] = useState(null)

  useEffect(() => {
    api.listScans().then(j => setJobs((Array.isArray(j) ? j : []).filter(x => x.status === 'completed').reverse())).catch(() => setJobs([]))
  }, [])

  if (jobs === null) return <Spinner label="Loading reports…" />

  return (
    <div className="page reports">
      <div className="page-head"><h1>Reports</h1></div>
      {!jobs.length ? (
        <PageEmpty icon="file" title="No completed scans to report on">
          Run a scan to the finish, then download its report here in any format.
        </PageEmpty>
      ) : (
        <DataTable
          rowKey={j => j.id}
          columns={[
            { key: 'target', label: 'Target', render: j => <span className="mono cell-target" onClick={() => go('#/scans/' + j.id)} style={{ cursor: 'pointer' }}>{j.target}</span> },
            { key: 'findings', label: 'Findings', width: '90px', align: 'right', render: j => j.summary ? j.summary.TotalFindings : 0 },
            { key: 'when', label: 'Finished', width: '110px', align: 'right', render: j => ago(j.updated_at) },
            {
              key: 'dl', label: 'Download', width: '320px', align: 'right', render: j => (
                <span className="report-formats">
                  {FORMATS.map(f => (
                    <a key={f.id} className="fmt-pill" href={api.reportURL(j.id, f.id)} target="_blank" rel="noreferrer"
                      onClick={() => toast('Report opened in a new tab')}><I.download width="12" height="12" /> {f.label}</a>
                  ))}
                </span>
              )
            },
          ]}
          rows={jobs}
        />
      )}
    </div>
  )
}
