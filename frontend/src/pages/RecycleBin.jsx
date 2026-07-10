import React, { useState, useEffect } from "react";
import { 
  Trash2, 
  RotateCcw, 
  ShieldAlert, 
  Activity, 
  FileText, 
  RefreshCw,
  CheckCircle,
  Database
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import SeverityBadge from "../components/common/SeverityBadge";
import { api } from "../api/client";

export default function RecycleBin() {
  const [activeTab, setActiveTab] = useState("incidents");
  const [loading, setLoading] = useState(true);
  const [deletedIncidents, setDeletedIncidents] = useState([]);
  const [deletedTelemetry, setDeletedTelemetry] = useState([]);
  const [actionMessage, setActionMessage] = useState(null);

  const loadData = async () => {
    try {
      setLoading(true);
      const [incidentsRes, telemetryRes] = await Promise.all([
        api.get("/api/incidents/deleted/all").catch(() => []),
        api.get("/api/telemetry/deleted/all").catch(() => ({ items: [] }))
      ]);
      setDeletedIncidents(incidentsRes || []);
      setDeletedTelemetry(telemetryRes?.items || []);
    } catch (e) {
      console.error("Failed to load recycle bin data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRestoreIncident = async (id) => {
    try {
      await api.post(`/api/incidents/${id}/restore`);
      showFlash("Incident restored successfully!");
      loadData();
    } catch (e) {
      console.error("Failed to restore incident", e);
    }
  };

  const handleRestoreTelemetry = async (id) => {
    try {
      await api.post(`/api/telemetry/${id}/restore`);
      showFlash("Telemetry log restored successfully!");
      loadData();
    } catch (e) {
      console.error("Failed to restore telemetry", e);
    }
  };

  const showFlash = (msg) => {
    setActionMessage(msg);
    setTimeout(() => setActionMessage(null), 3000);
  };

  if (loading) {
    return (
      <DashboardLayout title="Recycle Bin">
        <LoadingState message="Decrypting Recycle Bin records..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Recycle Bin">
      <div className="flex flex-col gap-6">
        
        {/* Header Summary */}
        <div className="p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
              <Database className="h-5 w-5 text-cyber-cyan" />
              <span>Soft-Deleted CNI Logs & Incidents</span>
            </h2>
            <p className="text-xs text-slate-400">
              Recover accidentally deleted security telemetry feeds and incidents back to active grids.
            </p>
          </div>
          <button 
            onClick={loadData}
            className="p-2 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>

        {/* Flash Message */}
        {actionMessage && (
          <div className="p-4 rounded bg-emerald-950/40 border border-emerald-500/50 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-pulse">
            <CheckCircle className="h-4.5 w-4.5 text-cyber-success" />
            <span>{actionMessage}</span>
          </div>
        )}

        {/* Tabs Bar */}
        <div className="flex gap-4 border-b border-slate-800 pb-px">
          <button
            onClick={() => setActiveTab("incidents")}
            className={`px-4 py-2 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all ${
              activeTab === "incidents" 
                ? "border-cyber-purple text-white bg-cyber-purple/5" 
                : "border-transparent text-slate-400 hover:text-white"
            }`}
          >
            Deleted Incidents ({deletedIncidents.length})
          </button>
          <button
            onClick={() => setActiveTab("telemetry")}
            className={`px-4 py-2 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all ${
              activeTab === "telemetry" 
                ? "border-cyber-cyan text-white bg-cyber-cyan/5" 
                : "border-transparent text-slate-400 hover:text-white"
            }`}
          >
            Deleted Telemetry Logs ({deletedTelemetry.length})
          </button>
        </div>

        {/* Main Content Area */}
        <div className="flex-1 min-h-[400px]">
          {activeTab === "incidents" ? (
            deletedIncidents.length === 0 ? (
              <div className="p-16 rounded-xl border border-dashed border-slate-800 bg-slate-950/20 text-center flex flex-col items-center justify-center">
                <Trash2 className="h-10 w-10 text-slate-600 mb-3" />
                <h4 className="text-sm font-bold text-white mb-1 font-mono">Incident Recycle Bin is Empty</h4>
                <p className="text-xs text-slate-500">No soft-deleted security incidents found in database.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {deletedIncidents.map((inc) => (
                  <div 
                    key={inc.id} 
                    className="p-5 rounded-xl bg-cyber-card/65 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between mb-3">
                        <span className="text-[10px] text-cyber-purple font-mono font-bold">
                          INCIDENT #{inc.id}
                        </span>
                        <SeverityBadge severity={inc.severity} />
                      </div>
                      <h4 className="text-sm font-bold text-white mb-2">{inc.title}</h4>
                      <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-4">
                        {inc.description || "No description provided."}
                      </p>
                    </div>
                    
                    <div className="flex items-center justify-between border-t border-slate-850 pt-3">
                      <span className="text-[9px] text-slate-500 font-mono">
                        Deleted via console
                      </span>
                      <button
                        onClick={() => handleRestoreIncident(inc.id)}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyber-purple/10 border border-cyber-purple/30 text-cyber-purple hover:bg-cyber-purple/20 transition-all text-xs font-semibold font-mono"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                        <span>Restore Incident</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )
          ) : (
            deletedTelemetry.length === 0 ? (
              <div className="p-16 rounded-xl border border-dashed border-slate-800 bg-slate-950/20 text-center flex flex-col items-center justify-center">
                <Trash2 className="h-10 w-10 text-slate-600 mb-3" />
                <h4 className="text-sm font-bold text-white mb-1 font-mono">Telemetry Log Recycle Bin is Empty</h4>
                <p className="text-xs text-slate-500">No soft-deleted security telemetry event feeds found.</p>
              </div>
            ) : (
              <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-900/60 font-mono text-[10px] uppercase text-slate-400 tracking-wider">
                        <th className="p-4">Timestamp</th>
                        <th className="p-4">Event Type</th>
                        <th className="p-4">Source IP</th>
                        <th className="p-4">Action</th>
                        <th className="p-4">Severity</th>
                        <th className="p-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850 text-xs">
                      {deletedTelemetry.map((log) => (
                        <tr key={log.id} className="hover:bg-slate-900/20 text-slate-300">
                          <td className="p-4 font-mono text-[10px] text-slate-500">
                            {log.timestamp ? new Date(log.timestamp).toLocaleString() : "N/A"}
                          </td>
                          <td className="p-4 font-mono font-bold text-cyber-cyan">{log.event_type}</td>
                          <td className="p-4 font-mono text-slate-400">{log.source_ip}</td>
                          <td className="p-4 truncate max-w-[150px]" title={log.action}>{log.action}</td>
                          <td className="p-4">
                            <SeverityBadge severity={log.severity} />
                          </td>
                          <td className="p-4 text-right">
                            <button
                              onClick={() => handleRestoreTelemetry(log.id)}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyber-cyan/10 border border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/20 transition-all text-[11px] font-semibold font-mono"
                            >
                              <RotateCcw className="h-3 w-3" />
                              <span>Restore</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )
          )}
        </div>

      </div>
    </DashboardLayout>
  );
}
