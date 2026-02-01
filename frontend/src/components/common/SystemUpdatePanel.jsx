import React from "react";
import useSystemUpdateStatus from "../../hooks/useSystemUpdateStatus";

const SystemUpdatePanel = () => {
  const { data, loading, error } = useSystemUpdateStatus();

  if (loading) return <div style={styles.info}>Checking for updates...</div>;
  if (error) return <div style={styles.error}>Unable to check updates</div>;
  if (!data) return null;

  const lastChecked = data.last_checked_at
    ? new Date(data.last_checked_at).toLocaleString()
    : "Never";

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

      {data.update_available ? (
        <div style={styles.updateBox}>
          A new system update is available!
        </div>
      ) : (
        <div style={styles.okBox}>
          Your system is up to date
        </div>
      )}
    </div>
  );
};

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
  okBox: {
    marginTop: "12px",
    padding: "10px",
    background: "#4caf50",
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
