import { useEffect, useState } from "react";

export default function Logs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetch("http://localhost:4000/api/logs")
      .then((res) => res.json())
      .then((data) => {
        setLogs(data.logs); // IMPORTANT
      })
      .catch((err) => console.error(err));
  }, []);

  return (
    <div>
      <h2>Logs Page</h2>

      <table border="1">
        <thead>
          <tr>
            <th>ID</th>
            <th>Event</th>
            <th>IP</th>
            <th>User</th>
            <th>Severity</th>
          </tr>
        </thead>

        <tbody>
          {logs.map((log) => (
            <tr key={log.id}>
              <td>{log.id}</td>
              <td>{log.event_name}</td>
              <td>{log.source_ip}</td>
              <td>{log.user_identity}</td>
              <td>{log.severity}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}