import { useState } from 'react'
import Sidebar from "./Sidebar.jsx";
import Dashboard from "./Dashboard.jsx";
import Alerts from "./Alerts.jsx";
import Logs from "./Logs.jsx";
import "./App.css";
export default function App() {
  const [page, setPage] = useState('dashboard')
  const pages = { dashboard: <Dashboard />, alerts: <Alerts />, logs: <Logs /> }
  return (
    <div className="layout">
      <Sidebar page={page} setPage={setPage} />
      <main className="main">{pages[page]}</main>
    </div>
  )
}