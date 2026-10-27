import React, { useEffect } from 'react'
import { I } from '../icons'
import { SEV, LABELS } from '../util'

/* SeverityDonut — the console's signature element: a ring of severity
   proportions with the finding total at its center. Pure SVG, severity tokens,
   legible in both themes. */
export function SeverityDonut({ counts, size = 168, stroke = 20 }) {
  const total = SEV.reduce((n, s) => n + (counts[s] || 0), 0)
  const r = (size - stroke) / 2
  const circ = 2 * Math.PI * r
  const cx = size / 2
  let offset = 0
  const segs = total === 0 ? [] : SEV.filter(s => counts[s] > 0).map(s => {
    const frac = counts[s] / total
    const seg = { s, dash: frac * circ, offset }
    offset += frac * circ
    return seg
  })
  return (
    <div className="donut">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`${total} findings by severity`}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={stroke} />
        {segs.map(({ s, dash, offset }) => (
          <circle key={s} cx={cx} cy={cx} r={r} fill="none" stroke={`var(--${s})`} strokeWidth={stroke}
            strokeDasharray={`${dash} ${circ - dash}`} strokeDashoffset={-offset}
            transform={`rotate(-90 ${cx} ${cx})`} strokeLinecap="butt" />
        ))}
        <text x={cx} y={cx - 4} textAnchor="middle" className="donut-total">{total}</text>
        <text x={cx} y={cx + 16} textAnchor="middle" className="donut-label">finding{total === 1 ? '' : 's'}</text>
      </svg>
      <div className="donut-legend">
        {SEV.map(s => (
          <div key={s} className="donut-leg-row">
            <span className="dot" style={{ background: `var(--${s})` }} />
            <span className="leg-name">{LABELS[s]}</span>
            <span className="leg-count">{counts[s] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export function StatCard({ label, value, tone, icon }) {
  const Icon = icon ? I[icon] : null
  return (
    <div className={`stat-card ${tone ? 'tone-' + tone : ''}`}>
      <div className="sc-top">
        <span className="sc-label">{label}</span>
        {Icon && <Icon className="sc-icon" width="16" height="16" />}
      </div>
      <div className="sc-value">{value}</div>
    </div>
  )
}

const STATUS_TONE = {
  completed: 'ok', running: 'run', queued: 'wait', failed: 'bad', cancelled: 'muted',
}

export function StatusPill({ status }) {
  const tone = STATUS_TONE[status] || 'muted'
  return <span className={`status-pill ${tone}`}><span className="sp-dot" />{status}</span>
}

export function DataTable({ columns, rows, empty, onRowClick, rowKey }) {
  return (
    <div className="data-table-wrap">
      <table className="data-table">
        <thead><tr>{columns.map(c => <th key={c.key} style={c.width ? { width: c.width } : undefined} className={c.align ? 'al-' + c.align : ''}>{c.label}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey ? rowKey(row) : i} className={onRowClick ? 'clickable' : ''} onClick={onRowClick ? () => onRowClick(row) : undefined}>
              {columns.map(c => <td key={c.key} className={c.align ? 'al-' + c.align : ''}>{c.render ? c.render(row) : row[c.key]}</td>)}
            </tr>
          ))}
          {!rows.length && <tr><td colSpan={columns.length} className="dt-empty">{empty || 'Nothing here yet.'}</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

export function Modal({ title, onClose, children, wide }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className={`modal-card ${wide ? 'wide' : ''}`} onClick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <h3>{title}</h3>
          <button className="icon-btn" aria-label="Close" onClick={onClose}><I.x width="16" height="16" /></button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  )
}

export function Field({ label, hint, children }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  )
}

export function Spinner({ label }) {
  return <div className="spinner-wrap"><span className="spinner" />{label && <span className="spinner-label">{label}</span>}</div>
}

export function PageEmpty({ icon, title, children }) {
  const Icon = icon ? I[icon] : I.shield
  return (
    <div className="page-empty">
      <Icon width="44" height="44" />
      <p className="pe-title">{title}</p>
      {children && <div className="pe-body">{children}</div>}
    </div>
  )
}
