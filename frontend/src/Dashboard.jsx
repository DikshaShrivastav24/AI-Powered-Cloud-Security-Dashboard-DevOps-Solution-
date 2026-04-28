import { useState, useEffect } from "react";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY
);

export default function Dashboard() {
  const [data, setData] = useState({
    totalAlerts: 0,
    openAlerts: 0,
    criticalAlerts: 0,
    currentThreatScore: 0,
  });
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  async function fetchDashboardData() {
    setLoading(true);
    const { data: rows, error } = await supabase
      .from("dashboard")
      .select("*")
      .single();

    if (error) {
      setError("Failed to load dashboard data.");
    } else {
      setData(rows);
    }
    setLoading(false);
  }

  const analyzeThreat = () => {
    setAnalyzing(true);
    setAnalysis(null);
    setError(null);

    // Simulate a brief analysis delay for UX
    setTimeout(() => {
      let riskLevel = "LOW";
      let text = "";

      if (data.criticalAlerts >= 5 || data.currentThreatScore >= 75) {
        riskLevel = "CRITICAL";
        text = `System risk is CRITICAL. ${data.criticalAlerts} critical alerts and a threat score of ${data.currentThreatScore}/100 indicate an active security incident. Immediate escalation and incident response are required.`;
      } else if (data.criticalAlerts >= 2 || data.currentThreatScore >= 50) {
        riskLevel = "HIGH";
        text = `System risk is HIGH due to ${data.criticalAlerts} critical alerts detected. Threat score stands at ${data.currentThreatScore}/100. Review and remediate critical alerts immediately before they escalate.`;
      } else if (data.openAlerts >= 5 || data.currentThreatScore >= 25) {
        riskLevel = "MEDIUM";
        text = `System risk is MEDIUM. ${data.openAlerts} open alerts are pending resolution with a threat score of ${data.currentThreatScore}/100. Monitor closely and prioritize open alert triage.`;
      } else {
        riskLevel = "LOW";
        text = `System risk is LOW. With only ${data.totalAlerts} total alerts and a threat score of ${data.currentThreatScore}/100, everything appears under control. Continue routine monitoring.`;
      }

      setAnalysis({ riskLevel, text });
      setAnalyzing(false);
    }, 800);
  };

  const getRiskColor = (level) => {
    const map = {
      LOW: { bg: "#0d2b1a", border: "#1a7a40", text: "#4ade80", badge: "#16a34a" },
      MEDIUM: { bg: "#2b2200", border: "#a16207", text: "#facc15", badge: "#ca8a04" },
      HIGH: { bg: "#2b1000", border: "#c2410c", text: "#fb923c", badge: "#ea580c" },
      CRITICAL: { bg: "#2b0000", border: "#b91c1c", text: "#f87171", badge: "#dc2626" },
      UNKNOWN: { bg: "#1a1a2e", border: "#3b3b5c", text: "#a5b4fc", badge: "#6366f1" },
    };
    return map[level] || map.UNKNOWN;
  };

  const getThreatScoreColor = (score) => {
    if (score >= 75) return "#f87171";
    if (score >= 50) return "#fb923c";
    if (score >= 25) return "#facc15";
    return "#4ade80";
  };

  const metrics = [
    { label: "Total Alerts", value: data.totalAlerts, icon: "⚠️" },
    { label: "Open Alerts", value: data.openAlerts, icon: "🔓" },
    { label: "Critical Alerts", value: data.criticalAlerts, icon: "🚨" },
    {
      label: "Threat Score",
      value: `${data.currentThreatScore}/100`,
      icon: "🎯",
      valueColor: getThreatScoreColor(data.currentThreatScore),
    },
  ];

  return (
    <div style={styles.page}>
      <div style={styles.container}>
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.headerLeft}>
            <div style={styles.logo}>🛡️</div>
            <div>
              <h1 style={styles.title}>ThreatWatch</h1>
              <p style={styles.subtitle}>Security Operations Dashboard</p>
            </div>
          </div>
          <div style={styles.statusDot}>
            <span style={styles.pulse} />
            <span style={styles.liveText}>LIVE</span>
          </div>
        </div>

        {/* Metric Cards */}
        {loading ? (
          <div style={styles.loadingBox}>
            <span style={styles.spinner}>⟳</span> Loading metrics...
          </div>
        ) : (
          <div style={styles.grid}>
            {metrics.map((m) => (
              <div key={m.label} style={styles.card}>
                <div style={styles.cardIcon}>{m.icon}</div>
                <div
                  style={{
                    ...styles.cardValue,
                    color: m.valueColor || "#e2e8f0",
                  }}
                >
                  {m.value}
                </div>
                <div style={styles.cardLabel}>{m.label}</div>
              </div>
            ))}
          </div>
        )}

        {/* Analyze Button */}
        <div style={styles.btnWrapper}>
          <button
            onClick={analyzeThreat}
            disabled={analyzing || loading}
            style={{
              ...styles.btn,
              opacity: analyzing || loading ? 0.6 : 1,
              cursor: analyzing || loading ? "not-allowed" : "pointer",
            }}
          >
            {analyzing ? (
              <>
                <span style={styles.spinnerSmall}>⟳</span> Analyzing...
              </>
            ) : (
              <>🤖 Analyze Threat</>
            )}
          </button>
        </div>

        {/* Error */}
        {error && (
          <div style={styles.errorBox}>
            <span>❌</span> {error}
          </div>
        )}

        {/* AI Analysis Result */}
        {analysis && (() => {
          const colors = getRiskColor(analysis.riskLevel);
          return (
            <div
              style={{
                ...styles.analysisBox,
                background: colors.bg,
                borderColor: colors.border,
              }}
            >
              <div style={styles.analysisHeader}>
                <span style={styles.analysisTitle}>🤖 AI Risk Analysis</span>
                <span
                  style={{
                    ...styles.badge,
                    background: colors.badge,
                  }}
                >
                  {analysis.riskLevel}
                </span>
              </div>
              <p style={{ ...styles.analysisText, color: colors.text }}>
                {analysis.text}
              </p>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    background: "#0a0f1e",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "24px",
    fontFamily: "'Courier New', monospace",
  },
  container: {
    width: "100%",
    maxWidth: "720px",
    display: "flex",
    flexDirection: "column",
    gap: "24px",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: "14px",
  },
  logo: {
    fontSize: "36px",
  },
  title: {
    margin: 0,
    fontSize: "26px",
    fontWeight: "700",
    color: "#e2e8f0",
    letterSpacing: "2px",
    textTransform: "uppercase",
  },
  subtitle: {
    margin: "2px 0 0",
    fontSize: "11px",
    color: "#64748b",
    letterSpacing: "1.5px",
    textTransform: "uppercase",
  },
  statusDot: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
  },
  pulse: {
    display: "inline-block",
    width: "10px",
    height: "10px",
    borderRadius: "50%",
    background: "#4ade80",
    boxShadow: "0 0 8px #4ade80",
  },
  liveText: {
    fontSize: "11px",
    color: "#4ade80",
    letterSpacing: "2px",
    fontWeight: "700",
  },
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, 1fr)",
    gap: "16px",
  },
  card: {
    background: "#111827",
    border: "1px solid #1e293b",
    borderRadius: "12px",
    padding: "24px 20px",
    textAlign: "center",
    transition: "border-color 0.2s",
  },
  cardIcon: {
    fontSize: "28px",
    marginBottom: "10px",
  },
  cardValue: {
    fontSize: "36px",
    fontWeight: "700",
    margin: "0 0 6px",
    letterSpacing: "1px",
  },
  cardLabel: {
    fontSize: "11px",
    color: "#64748b",
    textTransform: "uppercase",
    letterSpacing: "1.5px",
  },
  loadingBox: {
    textAlign: "center",
    padding: "40px",
    color: "#64748b",
    fontSize: "14px",
    background: "#111827",
    borderRadius: "12px",
    border: "1px solid #1e293b",
  },
  spinner: {
    display: "inline-block",
    animation: "spin 1s linear infinite",
    marginRight: "8px",
    fontSize: "18px",
  },
  spinnerSmall: {
    display: "inline-block",
    marginRight: "8px",
    fontSize: "14px",
  },
  btnWrapper: {
    display: "flex",
    justifyContent: "center",
  },
  btn: {
    background: "linear-gradient(135deg, #3b82f6, #6366f1)",
    color: "#fff",
    border: "none",
    borderRadius: "10px",
    padding: "14px 36px",
    fontSize: "15px",
    fontWeight: "700",
    letterSpacing: "1px",
    fontFamily: "'Courier New', monospace",
    display: "flex",
    alignItems: "center",
    gap: "8px",
    boxShadow: "0 4px 20px rgba(99,102,241,0.35)",
    transition: "transform 0.15s, box-shadow 0.15s",
  },
  errorBox: {
    background: "#2b0000",
    border: "1px solid #b91c1c",
    borderRadius: "10px",
    padding: "14px 20px",
    color: "#f87171",
    fontSize: "14px",
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  analysisBox: {
    borderRadius: "12px",
    border: "1px solid",
    padding: "20px 24px",
    transition: "all 0.3s ease",
  },
  analysisHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: "14px",
  },
  analysisTitle: {
    color: "#94a3b8",
    fontSize: "12px",
    letterSpacing: "1.5px",
    textTransform: "uppercase",
    fontWeight: "700",
  },
  badge: {
    color: "#fff",
    fontSize: "11px",
    fontWeight: "700",
    letterSpacing: "1.5px",
    padding: "4px 12px",
    borderRadius: "20px",
    textTransform: "uppercase",
  },
  analysisText: {
    margin: 0,
    fontSize: "15px",
    lineHeight: "1.7",
  },
};