import { useState } from 'react'
import Sidebar   from './components/Sidebar.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Alerts    from './pages/Alerts.jsx'
import Logs      from './pages/Logs.jsx'

export default function App() {
  const [page, setPage] = useState('dashboard')

  const pages = { dashboard: <Dashboard />, alerts: <Alerts />, logs: <Logs /> }

  return (
    <div className="layout">
      <Sidebar page={page} setPage={setPage} />
      <main className="main">
        {pages[page]}
      </main>
    </div>
  )
}
