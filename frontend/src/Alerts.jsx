import { useState } from 'react'
import { useFetch } from "./useFetch.js";

const SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 }

function timeAgo(iso) {
  const diff = Math.floor((Date.now() - new Date(iso)) / 60000)
  if (diff < 1)   return 'just now'
  if (diff < 60)  return `${diff}m ago`
  if (diff < 1440) return `${Math.floor(diff/60)}h ago`
  return `${Math.floor(diff/1440)}d ago`
}

const CLOUD_ICONS = { aws:'☁', azure:'◈', gcp:'⬡', kubernetes:'⎈' }

export default function Alerts() {
  const [sevFilter,    setSevFilter]    = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [cloudFilter,  setCloudFilter]  = useState('')

  const query = new URLSearchParams()
  if (sevFilter)    query.set('severity', sevFilter)
  if (statusFilter) query.set('status',   statusFilter)
  if (cloudFilter)  query.set('cloud',    cloudFilter)
  const qs = query.toString() ? `?${query.toString()}` : ''

  const { data, loading, error, refetch } = useFetch(`/api/alerts${qs}`, [qs])

  const alerts = data?.data ?? []
  const sorted = [...alerts].sort((a,b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9))

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Security Alerts</h2>
          <p>Real-time alerts across AWS · Azure · GCP · Kubernetes</p>
        </div>
        <button className="refresh-btn" onClick={refetch}>↺ Refresh</button>
      </div>

      {/* filters */}
      <div className="filters-bar">
        <span className="filter-label">Filter:</span>

        <select className="filter-select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
        </select>

        <select className="filter-select" value={cloudFilter} onChange={e => setCloudFilter(e.target.value)}>
          <option value="">All clouds</option>
          <option value="aws">AWS</option>
          <option value="azure">Azure</option>
          <option value="gcp">GCP</option>
          <option value="kubernetes">Kubernetes</option>
        </select>

        <span style={{ marginLeft:'auto', fontSize:'0.75rem', color:'var(--muted)' }}>
          {loading ? '…' : `${data?.total ?? 0} alerts`}
        </span>
      </div>

      {error && (
        <div className="error-box">⚠ {error} — make sure backend is running on port 4000</div>
      )}

      <div className="card" style={{ padding: 0, overflow:'hidden' }}>
        {loading ? (
          <div className="loading-box"><div className="spinner" /> Loading alerts…</div>
        ) : (
          <table className="alerts-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Threat Type</th>
                <th>Cloud</th>
                <th>Status</th>
                <th style={{ textAlign:'right' }}>Time</th>
              </tr>
            </thead>
            <tbody>
              {sorted.length === 0 ? (
                <tr><td colSpan={6} style={{ textAlign:'center', color:'var(--muted)', padding:40 }}>No alerts match filters</td></tr>
              ) : sorted.map(a => (
                <tr key={a.id}>
                  <td>
                    <span className={`badge badge-${a.severity}`}>
                      {a.severity === 'critical' && '●'} {a.severity}
                    </span>
                  </td>
                  <td>
                    <div className="alert-title">{a.title}</div>
                    <div style={{ fontSize:'0.7rem', color:'var(--muted)', marginTop:2 }}>
                      Resource: {a.resource_id ?? '—'}
                    </div>
                  </td>
                  <td style={{ color:'var(--muted)', fontSize:'0.78rem' }}>{a.threat_type}</td>
                  <td>
                    <span className="alert-cloud">
                      {CLOUD_ICONS[a.cloud_provider] ?? '◌'} {a.cloud_provider}
                    </span>
                  </td>
                  <td>
                    <span className={`status-badge status-${a.status}`}>{a.status}</span>
                  </td>
                  <td className="alert-time" style={{ textAlign:'right' }}>
                    {timeAgo(a.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* summary bar */}
      {!loading && !error && (
        <div style={{ display:'flex', gap:20, marginTop:14, fontSize:'0.75rem', color:'var(--muted)' }}>
          {['critical','high','medium','low'].map(s => {
            const count = alerts.filter(a => a.severity === s).length
            const colors = { critical:'var(--red)', high:'var(--orange)', medium:'var(--yellow)', low:'var(--green)' }
            return (
              <span key={s} style={{ display:'flex', alignItems:'center', gap:5 }}>
                <span style={{ width:8, height:8, borderRadius:'50%', background:colors[s], display:'inline-block' }} />
                <span style={{ color:colors[s], fontWeight:600 }}>{count}</span> {s}
              </span>
            )
          })}
        </div>
      )}
    </div>
  )
}