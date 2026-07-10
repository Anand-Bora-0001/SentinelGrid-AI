import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  User, 
  Clock, 
  Server, 
  Terminal, 
  CheckCircle,
  Play, 
  X,
  AlertCircle,
  Sparkles,
  ArrowRight,
  Trash2
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import SeverityBadge from "../components/common/SeverityBadge";
import { api } from "../api/client";
import { INCIDENT_STATUS, RESPONSE_ACTION_STATUS } from "../utils/constants";

export default function ActiveIncidents() {
  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [actions, setActions] = useState([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [generatingActions, setGeneratingActions] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const fetchIncidents = async () => {
    try {
      const data = await api.get("/api/incidents");
      setIncidents(data.items || []);
      
      // If we already have a selected incident, refresh its details
      if (selectedIncident) {
        const refreshed = data.items.find(i => i.id === selectedIncident.id);
        if (refreshed) {
          setSelectedIncident(refreshed);
        }
      }
    } catch (e) {
      console.warn("Failed to load incidents", e);
    }
  };

  const selectIncident = async (incident) => {
    setSelectedIncident(incident);
    setTimeline([]);
    setActions([]);
    try {
      // Fetch timeline
      const tlData = await api.get(`/api/incidents/${incident.id}/timeline`);
      setTimeline(tlData.timeline || []);

      // Fetch response actions
      const actData = await api.get(`/api/response/actions`, { incident_id: incident.id });
      setActions(actData || []);
    } catch (e) {
      console.warn("Failed to load incident details", e);
    }
  };

  useEffect(() => {
    const init = async () => {
      await fetchIncidents();
      setLoading(false);
    };
    init();
  }, []);

  const handleGenerateResponse = async () => {
    if (!selectedIncident) return;
    setGeneratingActions(true);
    try {
      await api.post(`/api/incidents/${selectedIncident.id}/response`);
      // Refresh actions
      const actData = await api.get(`/api/response/actions`, { incident_id: selectedIncident.id });
      setActions(actData || []);
      alert("AI has generated response playbooks. Please review and approve simulated execution.");
    } catch (err) {
      alert(`Response generation failed: ${err.message}`);
    } finally {
      setGeneratingActions(false);
    }
  };

  const handleApproveAction = async (actionId) => {
    setActionLoadingId(actionId);
    try {
      await api.post(`/api/response/actions/${actionId}/approve`);
      // Refresh actions and timeline
      const actData = await api.get(`/api/response/actions`, { incident_id: selectedIncident.id });
      setActions(actData || []);
      const tlData = await api.get(`/api/incidents/${selectedIncident.id}/timeline`);
      setTimeline(tlData.timeline || []);
      fetchIncidents();
    } catch (err) {
      alert(`Approval failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleRejectAction = async (actionId) => {
    setActionLoadingId(actionId);
    try {
      await api.post(`/api/response/actions/${actionId}/reject`);
      // Refresh actions
      const actData = await api.get(`/api/response/actions`, { incident_id: selectedIncident.id });
      setActions(actData || []);
      const tlData = await api.get(`/api/incidents/${selectedIncident.id}/timeline`);
      setTimeline(tlData.timeline || []);
      fetchIncidents();
    } catch (err) {
      alert(`Rejection failed: ${err.message}`);
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleResolveIncident = async () => {
    if (!selectedIncident) return;
    try {
      await api.put(`/api/incidents/${selectedIncident.id}`, { status: "resolved" });
      alert("Incident resolved successfully!");
      fetchIncidents();
      setSelectedIncident(null);
    } catch (err) {
      alert(`Failed to resolve incident: ${err.message}`);
    }
  };

  const handleDeleteIncident = async (id) => {
    if (!window.confirm("Are you sure you want to move this incident to the Recycle Bin?")) return;
    try {
      await api.delete(`/api/incidents/${id}`);
      alert("Incident moved to Recycle Bin.");
      fetchIncidents();
      setSelectedIncident(null);
    } catch (err) {
      alert(`Failed to delete incident: ${err.message}`);
    }
  };

  const handleClearAllIncidents = async () => {
    if (!window.confirm("Are you sure you want to move ALL incidents to the Recycle Bin?")) return;
    try {
      await api.delete("/api/incidents/clear");
      alert("All incidents moved to Recycle Bin.");
      fetchIncidents();
      setSelectedIncident(null);
    } catch (err) {
      alert(`Failed to clear incidents: ${err.message}`);
    }
  };

  const filteredIncidents = incidents.filter(i => {
    if (statusFilter === "all") return true;
    return i.status === statusFilter;
  });

  if (loading) {
    return (
      <DashboardLayout title="Incidents Console">
        <LoadingState message="Decrypting correlated security incidents..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Security Incidents Console">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8 h-[calc(100vh-130px)]">
        
        {/* Incidents List Column */}
        <div className="xl:col-span-1 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-6 flex flex-col h-full overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-850 pb-4 mb-4">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
              <ShieldAlert className="h-4.5 w-4.5 text-cyber-cyan" />
              <span>Incident Queues ({filteredIncidents.length})</span>
            </h3>
            
            <div className="flex items-center gap-2">
              <button
                onClick={handleClearAllIncidents}
                className="flex items-center justify-center p-1.5 rounded border border-red-900/50 bg-red-950/20 text-red-400 hover:text-red-300 hover:bg-red-900/30 transition-all"
                title="Clear All Incidents"
              >
                <Trash2 className="h-4 w-4" />
              </button>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-[10px] text-slate-400 rounded px-2.5 py-1.5 focus:outline-none focus:border-cyber-cyan font-mono"
              >
                <option value="all">ALL STATUSES</option>
                <option value="new">NEW</option>
                <option value="investigating">INVESTIGATING</option>
                <option value="contained">CONTAINED</option>
                <option value="resolved">RESOLVED</option>
              </select>
            </div>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3.5 pr-1">
            {filteredIncidents.length === 0 ? (
              <div className="text-center py-12 text-slate-500 font-mono text-xs">
                No incidents match the active filter.
              </div>
            ) : (
              filteredIncidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => selectIncident(inc)}
                  className={`p-4 rounded-xl border text-left cursor-pointer transition-all duration-200 ${
                    selectedIncident?.id === inc.id
                      ? "bg-slate-800/50 border-cyber-cyan shadow-cyber-neon"
                      : "bg-slate-900/60 border-slate-850 hover:border-slate-800"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="text-[10px] text-slate-500 font-mono leading-none">
                      INCIDENT ID #{inc.id}
                    </span>
                    <SeverityBadge severity={inc.severity} />
                  </div>
                  
                  <h4 className="text-xs font-bold text-white leading-tight mb-2 truncate">
                    {inc.title}
                  </h4>
                  
                  <p className="text-[11px] text-slate-400 line-clamp-2 mb-3">
                    {inc.description}
                  </p>

                  <div className="flex items-center justify-between border-t border-slate-850 pt-2 text-[10px] text-slate-500 font-mono">
                    <span className={`px-2 py-0.5 rounded border text-[9px] ${
                      INCIDENT_STATUS[inc.status]?.bg || "bg-slate-900"
                    }`}>
                      {INCIDENT_STATUS[inc.status]?.label || inc.status}
                    </span>
                    <span>{new Date(inc.created_at).toLocaleString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Selected Incident Details Panel */}
        <div className="xl:col-span-2 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-6 flex flex-col h-full overflow-hidden">
          {selectedIncident ? (
            <div className="flex-1 flex flex-col h-full overflow-hidden">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-850 pb-4 mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-xs text-cyber-cyan font-mono font-semibold">
                      INCIDENT ID #{selectedIncident.id}
                    </span>
                    <SeverityBadge severity={selectedIncident.severity} />
                    <span className={`px-2 py-0.5 rounded border text-[9px] font-mono font-medium ${
                      INCIDENT_STATUS[selectedIncident.status]?.bg || "bg-slate-900"
                    }`}>
                      {INCIDENT_STATUS[selectedIncident.status]?.label || selectedIncident.status}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-white">{selectedIncident.title}</h2>
                </div>

                <div className="flex items-center gap-3">
                  {selectedIncident.status !== "resolved" && (
                    <button
                      onClick={handleResolveIncident}
                      className="px-4 py-1.5 rounded bg-cyber-success/15 border border-cyber-success/30 text-cyber-success text-xs font-semibold hover:bg-cyber-success/20 transition-all font-mono"
                    >
                      Resolve Incident
                    </button>
                  )}
                  <button
                    onClick={() => handleDeleteIncident(selectedIncident.id)}
                    className="px-4 py-1.5 rounded bg-red-950/20 border border-red-500/30 text-red-400 text-xs font-semibold hover:bg-red-950/40 transition-all font-mono flex items-center gap-1.5"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    <span>Delete</span>
                  </button>
                </div>
              </div>

              {/* Grid content body */}
              <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 overflow-y-auto pr-1 pb-4">
                {/* Left details panel */}
                <div className="space-y-6">
                  {/* Overview details card */}
                  <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-850 text-xs">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono mb-3">
                      Incident Summary
                    </h3>
                    <p className="text-slate-300 leading-relaxed mb-4">{selectedIncident.description}</p>
                    
                    <div className="grid grid-cols-2 gap-4 font-mono text-[11px] text-slate-400 border-t border-slate-850 pt-3">
                      <div><span className="text-slate-550 block">CREATED BY</span> <strong className="text-white">{selectedIncident.created_by}</strong></div>
                      <div><span className="text-slate-550 block">BLAST RADIUS</span> <strong className="text-white">{selectedIncident.blast_radius || 0}%</strong></div>
                      <div><span className="text-slate-550 block">BUSINESS IMPACT</span> <strong className="text-white uppercase">{selectedIncident.business_impact}</strong></div>
                      <div><span className="text-slate-550 block">KILL CHAIN STAGE</span> <strong className="text-cyber-purple uppercase">{selectedIncident.attack_stage || "Initial Access"}</strong></div>
                    </div>
                  </div>

                  {/* MITRE and Affected assets */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-850 text-xs">
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono mb-2.5">
                        MITRE Techniques
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.mitre_techniques && selectedIncident.mitre_techniques.length > 0 ? (
                          selectedIncident.mitre_techniques.map(t => (
                            <span key={t} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-cyber-purple font-mono">
                              {t}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 italic">None mapped</span>
                        )}
                      </div>
                    </div>

                    <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-850 text-xs">
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono mb-2.5">
                        Affected Assets
                      </h4>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.affected_assets && selectedIncident.affected_assets.length > 0 ? (
                          selectedIncident.affected_assets.map(a => (
                            <span key={a.id || a} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-cyber-cyan font-mono">
                              {a.name || a}
                            </span>
                          ))
                        ) : (
                          <span className="text-slate-500 italic">None affected</span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Incident Timeline */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono mb-4">
                      Correlated Timeline Events
                    </h3>
                    <div className="relative border-l border-slate-850 pl-4 ml-2.5 space-y-4">
                      {timeline.map((entry, idx) => (
                        <div key={idx} className="relative">
                          {/* Timeline dot */}
                          <div className="absolute -left-[21.5px] top-1 h-3 w-3 rounded-full bg-slate-900 border-2 border-cyber-cyan" />
                          
                          <div className="text-xs">
                            <span className="text-[10px] text-slate-500 font-mono">
                              {new Date(entry.timestamp).toLocaleString()}
                            </span>
                            <p className="font-bold text-white mt-0.5">{entry.event}</p>
                            {entry.actor && (
                              <span className="text-[10px] text-slate-400 font-mono">
                                Actor: {entry.actor}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Right response action orchestrator panel */}
                <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-850/60 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2 text-cyber-purple font-mono text-[10px] uppercase tracking-widest mb-4">
                      <Sparkles className="h-4.5 w-4.5 animate-pulse" />
                      <span>Response Action Recommendations</span>
                    </div>

                    {actions.length === 0 ? (
                      <div className="text-center py-16">
                        <AlertCircle className="h-10 w-10 text-slate-600 mb-3 mx-auto" />
                        <p className="text-xs text-slate-500 font-mono max-w-[200px] mx-auto leading-relaxed mb-4">
                          No response actions are currently proposed for this threat.
                        </p>
                        
                        <button
                          onClick={handleGenerateResponse}
                          disabled={generatingActions}
                          className="px-4 py-2 bg-cyber-purple text-white text-xs font-semibold rounded hover:bg-cyber-purple/90 transition-all font-mono shadow-cyber-neon-purple flex items-center gap-2 mx-auto disabled:opacity-50"
                        >
                          <Sparkles className="h-3.5 w-3.5" />
                          <span>{generatingActions ? "GENERATING PLAYBOOKS..." : "GENERATE AI ACTIONS"}</span>
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {actions.map((act) => (
                          <div key={act.id} className="p-4 rounded-lg bg-slate-950 border border-slate-850">
                            <div className="flex justify-between items-start mb-2.5">
                              <div>
                                <span className="text-[10px] text-cyber-cyan font-mono font-semibold uppercase">
                                  {act.action_type}
                                </span>
                                <p className="text-xs font-bold text-white mt-0.5">Target: {act.target}</p>
                              </div>
                              <span className={`px-2 py-0.5 rounded border text-[9px] font-mono ${
                                RESPONSE_ACTION_STATUS[act.status]?.bg || "bg-slate-900"
                              }`}>
                                {RESPONSE_ACTION_STATUS[act.status]?.label || act.status}
                              </span>
                            </div>

                            <p className="text-[11px] text-slate-400 mb-3">{act.rationale}</p>
                            
                            {/* Action state decision */}
                            {act.status === "proposed" ? (
                              <div className="flex items-center gap-2 border-t border-slate-850/80 pt-3 mt-3">
                                <button
                                  onClick={() => handleApproveAction(act.id)}
                                  disabled={actionLoadingId === act.id}
                                  className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-cyber-success/15 border border-cyber-success/30 text-cyber-success text-[10px] font-bold rounded hover:bg-cyber-success/20 transition-all font-mono"
                                >
                                  <Play className="h-3 w-3 fill-current" />
                                  <span>APPROVE (SIMULATE)</span>
                                </button>
                                <button
                                  onClick={() => handleRejectAction(act.id)}
                                  disabled={actionLoadingId === act.id}
                                  className="px-3 py-1.5 bg-red-950/20 border border-red-500/20 text-red-400 text-[10px] font-bold rounded hover:bg-red-500/10 transition-all font-mono"
                                >
                                  <X className="h-3 w-3" />
                                </button>
                              </div>
                            ) : act.status === "approved" && act.simulation_result ? (
                              <div className="border-t border-slate-850/80 pt-3 mt-3 text-[10px] text-slate-400 font-mono space-y-1 bg-slate-950/80 p-2 rounded">
                                <p className="text-cyber-cyan font-bold mb-1">SIMULATION LOGS:</p>
                                <div><span className="text-slate-500">Affected Node:</span> {act.simulation_result.systems_affected?.join(", ")}</div>
                                <div><span className="text-slate-500">Rollback:</span> {act.simulation_result.rollback_procedure}</div>
                                <div className="text-amber-500 mt-1">⚠️ {act.simulation_result.note}</div>
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-slate-500 font-mono">
              <ShieldAlert className="h-12 w-12 text-slate-700 mb-3" />
              <p className="text-xs max-w-xs leading-relaxed">
                Select an incident campaign from the left queue to access the response actions controller and triage logs.
              </p>
            </div>
          )}
        </div>

      </div>
    </DashboardLayout>
  );
}
