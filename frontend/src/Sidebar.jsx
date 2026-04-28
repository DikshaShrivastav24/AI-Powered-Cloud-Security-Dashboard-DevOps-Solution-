export default function Sidebar({ page, setPage }) {
  const nav = [
    { id: 'dashboard', icon: '⬡', label: 'Dashboard'  },
    { id: 'alerts',    icon: '◈', label: 'Alerts'     },
    { id: 'logs',      icon: '≡', label: 'Logs'       },
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h1>CLOUD<br/>SECURITY</h1>
        <div style={{ marginTop: 8 }}>
          <span className="live-dot" />
          <span style={{ fontSize: '0.65rem', color: 'var(--green)', letterSpacing: '0.1em' }}>LIVE</span>
        </div>
      </div>

      <nav>
        {nav.map(n => (
          <div
            key={n.id}
            className={`nav-item ${page === n.id ? 'active' : ''}`}
            onClick={() => setPage(n.id)}
          >
            <span className="nav-icon">{n.icon}</span>
            {n.label}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div>Demo · No Auth</div>
        <div style={{ marginTop: 4, color: 'var(--accent)', fontSize: '0.65rem' }}>
          Backend: localhost:4000
        </div>
      </div>
    </aside>
  )
}
