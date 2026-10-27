import React, { useCallback, useEffect, useState } from 'react'
import { I } from './icons'
import { api } from './api'
import Dashboard from './pages/Dashboard'
import Targets from './pages/Targets'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Reports from './pages/Reports'
import Settings from './pages/Settings'

const NAV = [
  { hash: '#/dashboard', label: 'Dashboard', icon: 'grid' },
  { hash: '#/targets', label: 'Targets', icon: 'target' },
  { hash: '#/scans', label: 'Scans', icon: 'activity' },
  { hash: '#/reports', label: 'Reports', icon: 'file' },
  { hash: '#/settings', label: 'Settings', icon: 'gear' },
]

// parseRoute turns the URL hash into a route descriptor. Only the path portion
// is used; query params (e.g. ?key=) live on location.search, not the hash.
function parseRoute(hash) {
  const h = (hash || '').replace(/^#/, '') || '/dashboard'
  const parts = h.split('/').filter(Boolean) // ['scans','<id>']
  const section = parts[0] || 'dashboard'
  return { section, param: parts[1] || '' }
}

export default function App() {
  const [route, setRoute] = useState(() => parseRoute(location.hash))
  const [toast, setToast] = useState(null)
  const [version, setVersion] = useState('')
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem('vigil-theme') || 'dark' } catch { return 'dark' } })

  useEffect(() => {
    const onHash = () => setRoute(parseRoute(location.hash))
    window.addEventListener('hashchange', onHash)
    if (!location.hash) location.hash = '#/dashboard'
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => { document.documentElement.setAttribute('data-theme', theme); try { localStorage.setItem('vigil-theme', theme) } catch {} }, [theme])
  useEffect(() => { api.version().then(v => setVersion(v.version || '')).catch(() => {}) }, [])

  const go = useCallback((hash) => { location.hash = hash }, [])
  const showToast = useCallback((msg) => { setToast(msg); clearTimeout(showToast._t); showToast._t = setTimeout(() => setToast(null), 2000) }, [])

  const { section, param } = route
  const title = section === 'scans' && param ? 'Scan' : (NAV.find(n => n.hash === '#/' + section)?.label || 'Dashboard')

  let page
  switch (section) {
    case 'targets': page = <Targets go={go} toast={showToast} />; break
    case 'scans': page = param ? <ScanDetail key={param} id={param} go={go} toast={showToast} /> : <Scans go={go} toast={showToast} />; break
    case 'reports': page = <Reports go={go} toast={showToast} />; break
    case 'settings': page = <Settings toast={showToast} />; break
    default: page = <Dashboard go={go} toast={showToast} />
  }

  return (
    <div className="shell">
      <nav className="nav-rail">
        <div className="nav-logo"><I.shield width="26" height="26" /><span>vigil</span></div>
        <div className="nav-items">
          {NAV.map(n => {
            const Icon = I[n.icon]
            const active = ('#/' + section) === n.hash
            return (
              <a key={n.hash} href={n.hash} className={`nav-item ${active ? 'active' : ''}`} aria-current={active ? 'page' : undefined}>
                <Icon width="18" height="18" /><span>{n.label}</span>
              </a>
            )
          })}
        </div>
        <div className="nav-foot">{version && <span className="nav-ver">v{version}</span>}</div>
      </nav>

      <div className="shell-main">
        <header className="shell-top">
          <h1 className="top-title">{title}</h1>
          <div className="top-right">
            <button className="icon-btn" title="Toggle theme" aria-label="Toggle theme" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}>
              {theme === 'dark' ? <I.sun width="16" height="16" /> : <I.moon width="16" height="16" />}
            </button>
          </div>
        </header>
        <main className="shell-content">{page}</main>
      </div>

      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  )
}
