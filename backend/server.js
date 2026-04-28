// server.js — Cloud Security Dashboard (Demo, No Auth)
// Install: npm install express cors
// Run:     node server.js

const express = require('express');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 4000;

app.use(cors({ origin: '*' }));
app.use(express.json());

// ─── Sample Data ──────────────────────────────────────────────

const ago = (mins) => new Date(Date.now() - mins * 60000).toISOString();

const ALERTS = [
  { id: 'a1',  severity: 'critical', status: 'open',          cloud_provider: 'azure',      threat_type: 'PrivilegeEscalation', title: 'Privilege escalation on Azure VM',      created_at: ago(2)   },
  { id: 'a2',  severity: 'critical', status: 'open',          cloud_provider: 'aws',        threat_type: 'DDoS',                title: 'DDoS attack pattern on ALB',            created_at: ago(8)   },
  { id: 'a3',  severity: 'high',     status: 'open',          cloud_provider: 'aws',        threat_type: 'Misconfiguration',    title: 'Public S3 bucket with sensitive data',  created_at: ago(15)  },
  { id: 'a4',  severity: 'high',     status: 'investigating', cloud_provider: 'gcp',        threat_type: 'DataExfiltration',    title: 'Data exfiltration attempt via GCP',     created_at: ago(22)  },
  { id: 'a5',  severity: 'high',     status: 'open',          cloud_provider: 'gcp',        threat_type: 'BruteForce',          title: 'Brute-force SSH login on GCP bastion',  created_at: ago(35)  },
  { id: 'a6',  severity: 'high',     status: 'open',          cloud_provider: 'kubernetes', threat_type: 'ContainerEscape',     title: 'Container escape on Kubernetes node',   created_at: ago(48)  },
  { id: 'a7',  severity: 'medium',   status: 'resolved',      cloud_provider: 'gcp',        threat_type: 'Cryptomining',        title: 'Cryptomining process on GCP instance',  created_at: ago(90)  },
  { id: 'a8',  severity: 'medium',   status: 'open',          cloud_provider: 'aws',        threat_type: 'Misconfiguration',    title: 'Unencrypted RDS database found',        created_at: ago(120) },
  { id: 'a9',  severity: 'medium',   status: 'open',          cloud_provider: 'aws',        threat_type: 'Anomaly',             title: 'Unusual API calls from unknown IP',      created_at: ago(150) },
  { id: 'a10', severity: 'low',      status: 'open',          cloud_provider: 'azure',      threat_type: 'Compliance',          title: 'Expired SSL certificate on prod LB',    created_at: ago(180) },
];

const LOG_EVENTS = ['GetObject','PutObject','DeleteObject','CreateUser','AttachUserPolicy',
  'RunInstances','GetSecretValue','compute.instances.insert','storage.objects.get',
  'Microsoft.Compute/virtualMachines/write','pods/exec','secrets/get'];
const CLOUDS    = ['aws','azure','gcp','kubernetes'];
const SEVS      = ['critical','high','medium','low','info'];
const IPS       = ['10.0.1.42','10.0.2.15','52.92.1.5','198.51.100.1','203.0.113.5'];
const LOG_USERS = ['alice@corp.com','bob@corp.com','svc-pipeline','root','ANONYMOUS'];

const LOGS = Array.from({ length: 200 }, (_, i) => ({
  id:             'log-' + (i + 1),
  '@timestamp':   new Date(Date.now() - i * 240000).toISOString(),
  cloud_provider: CLOUDS[i % 4],
  event_name:     LOG_EVENTS[i % LOG_EVENTS.length],
  source_ip:      IPS[i % IPS.length],
  user_identity:  LOG_USERS[i % LOG_USERS.length],
  severity:       SEVS[i % 5],
  region:         ['us-east-1','eu-west-1','ap-southeast-1','us-central1'][i % 4],
  has_error:      i % 7 === 0,
  error_code:     i % 7 === 0 ? 'AccessDenied' : null,
}));

const THREAT_SCORES = Array.from({ length: 48 }, (_, i) => ({
  timestamp: new Date(Date.now() - (47 - i) * 1800000).toISOString(),
  score:     Math.round(20 + Math.abs(Math.sin(i * 0.4)) * 55 + (i > 30 ? 15 : 0)),
}));

// ─── Routes (fully public, no token needed) ───────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/dashboard/summary', (req, res) => {
  res.json({
    totalAlerts24h:       ALERTS.length,
    openAlerts:           ALERTS.filter(a => a.status === 'open').length,
    criticalAlerts:       ALERTS.filter(a => a.severity === 'critical').length,
    currentThreatScore:   THREAT_SCORES.at(-1).score,
    compliancePct:        84,
    totalResources:       401,
    highRiskResources:    15,
    totalVulnerabilities: 6,
    criticalVulns:        1,
    mttdMinutes:          8,
    mttrMinutes:          15,
    lastUpdated:          new Date().toISOString(),
  });
});

app.get('/api/alerts', (req, res) => {
  const { status, severity, cloud } = req.query;
  let data = [...ALERTS];
  if (status)   data = data.filter(a => a.status === status);
  if (severity) data = data.filter(a => a.severity === severity);
  if (cloud)    data = data.filter(a => a.cloud_provider === cloud);
  res.json({ total: data.length, data });
});

app.get('/api/logs', (req, res) => {
  const { cloud, severity, search, from = '0', size = '50' } = req.query;
  let data = [...LOGS];
  if (cloud && cloud !== 'all') data = data.filter(l => l.cloud_provider === cloud);
  if (severity) data = data.filter(l => l.severity === severity);
  if (search)   data = data.filter(l => l.event_name.includes(search) || l.source_ip.includes(search));
  const f = parseInt(from), s = Math.min(parseInt(size), 100);
  res.json({ total: data.length, from: f, size: s, logs: data.slice(f, f + s) });
});

app.get('/api/threats/scores', (req, res) => res.json(THREAT_SCORES));

app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT + ' — no auth required');
  console.log('  GET /health');
  console.log('  GET /api/dashboard/summary');
  console.log('  GET /api/alerts');
  console.log('  GET /api/logs');
  console.log('  GET /api/threats/scores');
});