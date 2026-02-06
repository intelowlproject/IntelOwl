import React from "react";
import useSystemUpdateStatus from "../../hooks/useSystemUpdateStatus";

function SystemUpdatePanel({ compact = false }) {
  const { data, loading, error } = useSystemUpdateStatus();

  if (loading || error) return null;
  if (!data?.update_available) return null;

  const lastChecked = data.last_checked_at
    ? new Date(data.last_checked_at).toLocaleString()
    : "Never";

  if (compact) {
    return (
      <div className="system-update-compact">
        <strong>A new system update is available.</strong>
        <span>
          {" "}
          Current: {data.current_version || "Unknown"} → Latest:{" "}
          {data.latest_version || "Unknown"}
        </span>
      </div>
    );
  }

  return (
    <div style={styles.card}>
      <h3 style={styles.title}>System Updates</h3>

      <div style={styles.row}>
        <strong>Current Version:</strong>
        <span>{data.current_version || "Unknown"}</span>
      </div>

      <div style={styles.row}>
        <strong>Latest Version:</strong>
        <span>{data.latest_version || "Unknown"}</span>
      </div>

      <div style={styles.row}>
        <strong>Last Checked:</strong>
        <span>{lastChecked}</span>
      </div>

      <div style={styles.updateBox}>A new system update is available!</div>
    </div>
  );
}

const styles = {
  card: {
    padding: "16px",
    borderRadius: "10px",
    background: "#1e1e1e",
    color: "#fff",
    marginBottom: "20px",
    boxShadow: "0 2px 10px rgba(0,0,0,0.4)",
  },
  title: {
    marginBottom: "12px",
  },
  row: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: "8px",
  },
  updateBox: {
    marginTop: "12px",
    padding: "10px",
    background: "#ff9800",
    borderRadius: "6px",
    fontWeight: "bold",
  },
  error: {
    color: "#ff4d4f",
  },
  info: {
    color: "#bbb",
  },
};

export default SystemUpdatePanel;
