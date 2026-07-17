import React, { useState, useEffect } from "react";
import { 
  Play, 
  Activity, 
  Cpu, 
  CheckCircle, 
  AlertTriangle,
  RefreshCw,
  Trash2
} from "lucide-react";
import { api } from "../../api/client";

export default function Topbar({ title }) {
  const [loading, setLoading] = useState(false);
  const [health, setHealth] = useState(null);

  const fetchHealth = async () => {
    try {
      const data = await api.get("/health");
      setHealth(data);
    } catch (e) {
      console.warn("Failed to fetch server health metrics", e);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulate = async () => {
    setLoading(true);
    try {
      await api.post("/api/telemetry/simulate?count=50&include_attack=true");
      alert("Successfully injected 50 simulated telemetry events and multi-stage CNI campaign!");
      window.location.reload(); // Refresh the page to reload state
    } catch (err) {
      alert(`Simulation injection failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleClearLogs = async () => {
    setLoading(true);
    try {
      await api.delete("/api/telemetry/clear");
      await api.delete("/api/incidents/clear");
      await api.delete("/api/audit/clear");
      alert("All logs, incidents, and audit trails have been cleared and moved to the Recycle Bin.");
      window.location.reload();
    } catch (err) {
      alert(`Clear failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Determine health level
  const activeIncidents = health?.database?.metrics?.active_incidents ?? 0;
  const criticalCount = health?.database?.metrics?.vulnerability_count ?? 0;

  let healthStatus = {
    label: "Optimal Grid Status",
    color: "text-emerald-400 border-emerald-500/20 bg-emerald-500/5",
    icon: CheckCircle
  };

  if (activeIncidents > 0) {
    if (activeIncidents >= 2) {
      healthStatus = {
        label: "Grid Under Active Attack",
        color: "text-red-400 border-red-500/20 bg-red-500/5 animate-pulse",
        icon: AlertTriangle
      };
    } else {
      healthStatus = {
        label: "Grid Degraded (Alerts Active)",
        color: "text-amber-400 border-amber-500/20 bg-amber-500/5",
        icon: AlertTriangle
      };
    }
  }

  const HealthIcon = healthStatus.icon;

  return (
    <header className="h-16 glass-panel border-b border-slate-800 flex items-center justify-between px-8 z-10">
      {/* Title */}
      <div>
        <h2 className="text-base font-bold text-white tracking-tight uppercase">
          {title || "Security Operations Console"}
        </h2>
      </div>

      {/* Grid status & quick actions */}
      <div className="flex items-center gap-6">
        {/* System Health */}
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium font-mono ${healthStatus.color}`}>
          <HealthIcon className="h-3.5 w-3.5" />
          <span>{healthStatus.label}</span>
        </div>

        {/* AI Engine Status */}
        <div className="flex items-center gap-2 border border-slate-800 bg-slate-950/60 rounded-full px-3 py-1.5 text-xs text-slate-400">
          <Cpu className="h-3.5 w-3.5 text-cyber-purple animate-pulse" />
          <span className="font-mono text-[10px] text-cyber-purple uppercase tracking-wider">
            AI Resilience Core Active
          </span>
        </div>

        {/* Clear Logs trigger */}
        <button
          onClick={handleClearLogs}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 transition-all font-mono disabled:opacity-50"
        >
          {loading ? (
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Trash2 className="h-3.5 w-3.5" />
          )}
          <span>Clear Logs</span>
        </button>

        {/* Simulation trigger */}
        <button
          onClick={handleSimulate}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyber-cyan text-cyber-bg hover:bg-cyber-cyan/90 transition-all font-mono shadow-md disabled:opacity-50"
        >
          {loading ? (
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5 fill-current" />
          )}
          <span>{loading ? "Simulating..." : "Seed Threat Feed"}</span>
        </button>
      </div>
    </header>
  );
}
