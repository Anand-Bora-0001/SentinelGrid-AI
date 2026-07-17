import React, { useState, useEffect } from "react";
import { 
  History, 
  Search, 
  Download, 
  Filter,
  User,
  Clock,
  Database,
  Trash2,
  Activity,
  RotateCcw
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import SeverityBadge from "../components/common/SeverityBadge";
import { api } from "../api/client";

export default function AuditTrailView() {
  const [activeTab, setActiveTab] = useState("audit");
  const [loading, setLoading] = useState(true);
  
  // Compliance Audit Logs State
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(25);
  
  // Compliance Filters
  const [filterActor, setFilterActor] = useState("");
  const [filterAction, setFilterAction] = useState("");
  const [filterResource, setFilterResource] = useState("");

  // Telemetry Logs State
  const [telemetryLogs, setTelemetryLogs] = useState([]);
  const [telemetryTotal, setTelemetryTotal] = useState(0);
  const [telemetryPage, setTelemetryPage] = useState(1);
  const [telemetryLimit] = useState(25);

  const fetchLogs = async () => {
    try {
      const params = { page, limit };
      if (filterActor) params.actor = filterActor;
      if (filterAction) params.action = filterAction;
      if (filterResource) params.resource_type = filterResource;

      const data = await api.get("/api/audit", params);
      setLogs(data.items || []);
      setTotal(data.total || 0);
    } catch (e) {
      console.warn("Failed to load audit logs", e);
    }
  };

  const fetchTelemetry = async () => {
    try {
      const data = await api.get("/api/telemetry", { page: telemetryPage, limit: telemetryLimit });
      setTelemetryLogs(data.items || []);
      setTelemetryTotal(data.total || 0);
    } catch (e) {
      console.warn("Failed to load telemetry logs", e);
    }
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      if (activeTab === "audit") {
        await fetchLogs();
      } else {
        await fetchTelemetry();
      }
      setLoading(false);
    };
    init();
  }, [activeTab, page, telemetryPage, filterActor, filterAction, filterResource]);

  const handleDeleteTelemetry = async (id) => {
    if (!window.confirm("Are you sure you want to move this log to the Recycle Bin?")) return;
    try {
      await api.delete(`/api/telemetry/${id}`);
      alert("Telemetry log moved to Recycle Bin.");
      fetchTelemetry();
    } catch (err) {
      alert(`Failed to delete log: ${err.message}`);
    }
  };

  const handleClearAllTelemetry = async () => {
    if (!window.confirm("Are you sure you want to clear ALL logs, incidents, and dashboard data? This will reset the demo data.")) return;
    try {
      await api.delete("/api/telemetry/clear");
      await api.delete("/api/incidents/clear");
      await api.delete("/api/audit/clear");
      alert("All dashboard data and logs have been cleared.");
      fetchTelemetry();
      if (activeTab === "audit") {
        fetchLogs();
      }
    } catch (err) {
      alert(`Failed to clear logs: ${err.message}`);
    }
  };

  const handleExport = (format) => {
    fetch(`/api/audit/export?format=${format}`, {
      headers: api.headers()
    })
    .then(res => res.blob())
    .then(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinelgrid_audit_log.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    })
    .catch(err => {
      alert(`Export failed: ${err.message}`);
    });
  };

  const totalPages = activeTab === "audit" 
    ? (Math.ceil(total / limit) || 1) 
    : (Math.ceil(telemetryTotal / telemetryLimit) || 1);

  const currentPage = activeTab === "audit" ? page : telemetryPage;

  if (loading && page === 1 && telemetryPage === 1) {
    return (
      <DashboardLayout title="Audit Trail">
        <LoadingState message="Decrypting secure SOC audit logs..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Platform Audit Trail & Compliance logs">
      <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-6 flex flex-col h-[calc(100vh-130px)] overflow-hidden">
        
        {/* Header Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-850 pb-4 mb-4">
          <div className="flex gap-4">
            <button
              onClick={() => setActiveTab("audit")}
              className={`px-4 py-2 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all ${
                activeTab === "audit" 
                  ? "border-cyber-cyan text-white" 
                  : "border-transparent text-slate-400 hover:text-white"
              }`}
            >
              Compliance Audit Trail
            </button>
            <button
              onClick={() => setActiveTab("telemetry")}
              className={`px-4 py-2 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all ${
                activeTab === "telemetry" 
                  ? "border-cyber-purple text-white" 
                  : "border-transparent text-slate-400 hover:text-white"
              }`}
            >
              Security Telemetry Feeds
            </button>
          </div>

          {activeTab === "audit" && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleExport("csv")}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-800 bg-slate-900 text-slate-300 hover:text-white font-mono text-xs font-semibold transition-all hover:bg-slate-950"
              >
                <Download className="h-3.5 w-3.5" />
                <span>EXPORT CSV</span>
              </button>
              <button
                onClick={() => handleExport("json")}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-800 bg-slate-900 text-slate-300 hover:text-white font-mono text-xs font-semibold transition-all hover:bg-slate-950"
              >
                <Download className="h-3.5 w-3.5" />
                <span>EXPORT JSON</span>
              </button>
            </div>
          )}

          {activeTab === "telemetry" && (
            <div className="flex items-center gap-2">
              <button
                onClick={handleClearAllTelemetry}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-red-900/50 bg-red-950/20 text-red-400 hover:text-red-300 hover:bg-red-900/30 font-mono text-xs font-semibold transition-all"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>CLEAR ALL LOGS</span>
              </button>
            </div>
          )}
        </div>

        {/* Audit Filter Block */}
        {activeTab === "audit" && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6 bg-slate-950/45 p-4 border border-slate-850 rounded-lg">
            <div>
              <label className="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 font-mono">
                Filter by Actor
              </label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-500">
                  <User className="h-3.5 w-3.5" />
                </span>
                <input
                  type="text"
                  value={filterActor}
                  onChange={(e) => { setFilterActor(e.target.value); setPage(1); }}
                  placeholder="e.g. admin"
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-850 text-xs text-white rounded focus:outline-none focus:border-cyber-cyan font-mono placeholder-slate-650"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 font-mono">
                Filter by Action
              </label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-500">
                  <Clock className="h-3.5 w-3.5" />
                </span>
                <input
                  type="text"
                  value={filterAction}
                  onChange={(e) => { setFilterAction(e.target.value); setPage(1); }}
                  placeholder="e.g. login, approve"
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-850 text-xs text-white rounded focus:outline-none focus:border-cyber-cyan font-mono placeholder-slate-650"
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1 font-mono">
                Filter by Resource
              </label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-2.5 flex items-center text-slate-500">
                  <Database className="h-3.5 w-3.5" />
                </span>
                <input
                  type="text"
                  value={filterResource}
                  onChange={(e) => { setFilterResource(e.target.value); setPage(1); }}
                  placeholder="e.g. incident, telemetry"
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-850 text-xs text-white rounded focus:outline-none focus:border-cyber-cyan font-mono placeholder-slate-650"
                />
              </div>
            </div>
          </div>
        )}

        {/* Data Table */}
        <div className="flex-1 overflow-y-auto pr-1">
          {activeTab === "audit" ? (
            logs.length === 0 ? (
              <div className="text-center py-20 text-slate-500 font-mono text-xs">
                No audit logs match current filter configuration.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-sans">
                <thead>
                  <tr className="border-b border-slate-800/85 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                    <th className="py-2.5 px-2">TIMESTAMP</th>
                    <th className="py-2.5 px-2">ACTOR</th>
                    <th className="py-2.5 px-2">ROLE</th>
                    <th className="py-2.5 px-2">ACTION</th>
                    <th className="py-2.5 px-2">RESOURCE</th>
                    <th className="py-2.5 px-2">RESOURCE ID</th>
                    <th className="py-2.5 px-2">IP ADDRESS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850/50">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/40 font-mono text-[11px] text-slate-400">
                      <td className="py-3 px-2 text-slate-500">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-2 text-white font-semibold">
                        {log.actor}
                      </td>
                      <td className="py-3 px-2 uppercase text-[10px]">
                        {log.actor_role || "system"}
                      </td>
                      <td className="py-3 px-2">
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-cyber-cyan">
                          {log.action}
                        </span>
                      </td>
                      <td className="py-3 px-2 uppercase text-[10px] text-cyber-purple">
                        {log.resource_type}
                      </td>
                      <td className="py-3 px-2">
                        {log.resource_id || "-"}
                      </td>
                      <td className="py-3 px-2 text-slate-500">
                        {log.ip_address || "local"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          ) : (
            telemetryLogs.length === 0 ? (
              <div className="text-center py-20 text-slate-500 font-mono text-xs">
                No security telemetry feed logs loaded.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-sans">
                <thead>
                  <tr className="border-b border-slate-800/85 text-[10px] text-slate-500 uppercase tracking-wider font-mono">
                    <th className="py-2.5 px-2">TIMESTAMP</th>
                    <th className="py-2.5 px-2">EVENT TYPE</th>
                    <th className="py-2.5 px-2">SOURCE IP</th>
                    <th className="py-2.5 px-2">ACTION</th>
                    <th className="py-2.5 px-2">RISK SCORE</th>
                    <th className="py-2.5 px-2">SEVERITY</th>
                    <th className="py-2.5 px-2 text-right">ACTIONS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-850/50">
                  {telemetryLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-900/40 font-mono text-[11px] text-slate-400">
                      <td className="py-3 px-2 text-slate-500">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="py-3 px-2 text-cyber-cyan font-bold">
                        {log.event_type}
                      </td>
                      <td className="py-3 px-2">
                        {log.source_ip}
                      </td>
                      <td className="py-3 px-2 truncate max-w-[150px]" title={log.action}>
                        {log.action}
                      </td>
                      <td className={`py-3 px-2 font-bold ${
                        log.risk_score > 70 ? "text-rose-400 shadow-md" : "text-emerald-400"
                      }`}>
                        {log.risk_score}%
                      </td>
                      <td className="py-3 px-2">
                        <SeverityBadge severity={log.severity} />
                      </td>
                      <td className="py-3 px-2 text-right">
                        <button
                          onClick={() => handleDeleteTelemetry(log.id)}
                          className="p-1.5 rounded bg-red-950/20 border border-red-500/30 text-red-400 hover:bg-red-950/40 transition-colors"
                          title="Move to Recycle Bin"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
        </div>

        {/* Pagination Footer */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between border-t border-slate-850 pt-4 mt-4 text-xs font-mono">
            <span className="text-slate-500">
              Showing page {currentPage} of {totalPages}
            </span>
            
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  if (activeTab === "audit") {
                    setPage(p => Math.max(p - 1, 1));
                  } else {
                    setTelemetryPage(p => Math.max(p - 1, 1));
                  }
                }}
                disabled={currentPage === 1}
                className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:hover:text-slate-400"
              >
                Previous
              </button>
              <button
                onClick={() => {
                  if (activeTab === "audit") {
                    setPage(p => Math.min(p + 1, totalPages));
                  } else {
                    setTelemetryPage(p => Math.min(p + 1, totalPages));
                  }
                }}
                disabled={currentPage === totalPages}
                className="px-3 py-1 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:hover:text-slate-400"
              >
                Next
              </button>
            </div>
          </div>
        )}
        
      </div>
    </DashboardLayout>
  );
}
