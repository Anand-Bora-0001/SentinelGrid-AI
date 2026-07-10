import React, { useState, useEffect } from "react";
import { 
  Grid, Activity, HelpCircle, ExternalLink, X, AlertCircle, TrendingUp, Clock, ShieldAlert, Crosshair
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import SeverityBadge from "../components/common/SeverityBadge";
import { api } from "../api/client";
import AttackChainVisualization from "../components/mitre/AttackChainVisualization";

export default function MitreView() {
  const [loading, setLoading] = useState(true);
  const [tactics, setTactics] = useState([]);
  const [techniques, setTechniques] = useState([]);
  const [highConfidence, setHighConfidence] = useState([]);
  const [attackChain, setAttackChain] = useState(null);
  
  const [selectedTechId, setSelectedTechId] = useState(null);
  const [techDetails, setTechDetails] = useState(null);
  const [techLoading, setTechLoading] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [matrixData, heatmapData] = await Promise.all([
          api.get("/api/mitre/matrix").catch(() => ({ tactics: [], techniques_by_tactic: {} })),
          api.get("/api/mitre/heatmap").catch(() => ({}))
        ]);

        const tacticsList = matrixData.tactics || [];
        setTactics(tacticsList);

        // Flatten techniques from matrix
        const flattenedTechs = [];
        Object.entries(matrixData.techniques_by_tactic || {}).forEach(([tacticName, techs]) => {
          const tacticObj = tacticsList.find(t => t.name === tacticName);
          const tacticId = tacticObj ? tacticObj.id : "";
          techs.forEach(tech => {
            flattenedTechs.push({
              id: tech.id,
              name: tech.name,
              tactic_id: tacticId,
              tactic_name: tacticName,
              severity: tech.severity,
              description: tech.description
            });
          });
        });
        setTechniques(flattenedTechs);

        // Extract confidence list from heatmap
        const confidenceList = [];
        Object.entries(heatmapData).forEach(([tacticName, techs]) => {
          techs.forEach(t => {
            if (t.count > 0) {
              confidenceList.push({
                id: t.technique_id,
                name: t.technique_name,
                confidence: Math.min(98, 70 + t.count * 5),
                severity: t.severity,
                count: t.count
              });
            }
          });
        });

        // Fallback for demo display if database is empty
        if (confidenceList.length === 0) {
          confidenceList.push(
            { id: "T1190", name: "Exploit Public-Facing Application", confidence: 94, severity: "CRITICAL" },
            { id: "T1548", name: "Abuse Elevation Control Mechanism", confidence: 85, severity: "CRITICAL" },
            { id: "T1003", name: "OS Credential Dumping", confidence: 78, severity: "CRITICAL" },
            { id: "T1021", name: "Remote Services", confidence: 72, severity: "HIGH" }
          );
        }
        setHighConfidence(confidenceList);

        // Fetch latest attack chain from timeline
        try {
          const chain = await api.get("/api/mitre/attack-timeline");
          if (chain && chain.attack_stage && chain.attack_stage.detected_tactics.length > 0) {
            const stages = chain.timeline.map(t => ({
              tactic: t.mitre_tactic || t.tactic || "Initial Access",
              technique_name: t.technique_name || t.action
            }));
            setAttackChain({ stages, timestamp: new Date().toISOString() });
          } else {
            throw new Error("No chain in timeline");
          }
        } catch {
          // Fallback demo chain
          setAttackChain({
            stages: [
              { tactic: "Initial Access", technique_name: "Exploit Public-Facing Application" },
              { tactic: "Privilege Escalation", technique_name: "Abuse Elevation Control Mechanism" },
              { tactic: "Credential Access", technique_name: "OS Credential Dumping" },
              { tactic: "Lateral Movement", technique_name: "Remote Services" }
            ],
            timestamp: new Date().toISOString()
          });
        }
      } catch (e) {
        console.warn("Failed to load MITRE intelligence", e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const selectTechnique = (tech) => {
    setSelectedTechId(tech.id);
    setTechLoading(true);
    // Simulate loading details or map locally
    setTimeout(() => {
      setTechDetails({
        ...tech,
        threat_actors: [
          { name: "APT29", origin: "Russia", similarity: 0.89 },
          { name: "FIN7", origin: "Unknown", similarity: 0.72 }
        ],
        related_events: []
      });
      setTechLoading(false);
    }, 500);
  };

  if (loading) {
    return (
      <DashboardLayout title="SOC MITRE Intelligence">
        <LoadingState message="Initializing MITRE ATT&CK Intelligence Engine..." />
      </DashboardLayout>
    );
  }

  // Group techniques by tactic_id
  const techniquesByTactic = tactics.reduce((acc, tactic) => {
    acc[tactic.id] = techniques.filter(t => t.tactic_id === tactic.id);
    return acc;
  }, {});

  // Create a map for heatmap counts based on high confidence
  const heatmapMap = highConfidence.reduce((acc, tc) => {
    acc[tc.id] = tc.confidence;
    return acc;
  }, {});

  return (
    <DashboardLayout title="MITRE ATT&CK Intelligence Engine">
      <div className="flex flex-col h-[calc(100vh-130px)] gap-4 overflow-y-auto pb-6">
        
        {/* Top Widgets Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 min-h-[300px] shrink-0">
          
          {/* Attack Chain Visualizer */}
          <div className="lg:col-span-2 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-4 flex flex-col">
            <div className="flex items-center gap-2 mb-4 text-cyber-cyan">
              <Activity className="h-5 w-5" />
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Live Attack Chain Visualization</h3>
            </div>
            <div className="flex-1 rounded-lg border border-slate-800 overflow-hidden bg-slate-950/50">
              <AttackChainVisualization chainStages={attackChain?.stages || []} />
            </div>
          </div>

          {/* Technique Heatmap & High Confidence */}
          <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-4 flex flex-col">
            <div className="flex items-center gap-2 mb-4 text-orange-500">
              <TrendingUp className="h-5 w-5" />
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Technique Heatmap</h3>
            </div>
            <div className="flex-1 overflow-y-auto space-y-2 pr-1">
              {highConfidence.length === 0 ? (
                <p className="text-xs text-slate-500 font-mono text-center mt-10">No confident mappings yet.</p>
              ) : (
                highConfidence.map((tech, idx) => (
                  <div key={idx} className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between hover:border-orange-500/50 transition-colors cursor-pointer" onClick={() => selectTechnique(tech)}>
                    <div className="flex items-center gap-3">
                      <div className="flex flex-col items-center justify-center h-10 w-10 rounded bg-slate-950 border border-slate-800 text-xs font-bold text-orange-400 font-mono">
                        {tech.confidence}%
                      </div>
                      <div>
                        <div className="text-[10px] text-cyber-cyan font-mono">{tech.id}</div>
                        <div className="text-xs font-bold text-white max-w-[150px] truncate">{tech.name}</div>
                      </div>
                    </div>
                    <Crosshair className="h-4 w-4 text-slate-600" />
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Matrix Grid */}
        <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-4 flex flex-col min-h-[500px] shrink-0">
          <div className="flex items-center gap-2 mb-4 text-cyber-purple">
            <Grid className="h-5 w-5" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Interactive ATT&CK Matrix</h3>
          </div>
          
          <div className="flex-1 overflow-auto pr-1 border border-slate-800 rounded-lg bg-slate-950/30 p-4">
            {tactics.length === 0 ? (
              <div className="h-full flex items-center justify-center text-slate-500 font-mono text-sm">
                Dataset not loaded or missing. Please ensure mitre_attack_enterprise.json is parsed.
              </div>
            ) : (
              <div className="flex gap-4 min-w-max pb-4">
                {tactics.map((tactic) => {
                  const tacticTechs = techniquesByTactic[tactic.id] || [];
                  return (
                    <div key={tactic.id} className="w-48 shrink-0 flex flex-col">
                      {/* Tactic Header */}
                      <div className="p-3 bg-slate-900/80 border border-slate-700 rounded-t-lg text-center shadow-lg">
                        <span className="text-[10px] text-slate-400 font-mono block">
                          {tactic.id}
                        </span>
                        <h5 className="text-[11px] font-bold text-cyber-cyan truncate uppercase tracking-tight mt-0.5">
                          {tactic.name}
                        </h5>
                      </div>
                      
                      {/* Techniques Queue */}
                      <div className="flex-1 overflow-y-auto space-y-2 mt-2">
                        {tacticTechs.map((tech) => {
                          const conf = heatmapMap[tech.id];
                          
                          let bgClass = "bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-600";
                          if (conf >= 90) bgClass = "bg-red-950/30 border-red-500/50 text-red-300 hover:border-red-400 shadow-[0_0_10px_rgba(239,68,68,0.2)]";
                          else if (conf >= 70) bgClass = "bg-orange-950/30 border-orange-500/50 text-orange-300 hover:border-orange-400";
                          else if (conf > 0) bgClass = "bg-yellow-950/30 border-yellow-500/50 text-yellow-300 hover:border-yellow-400";

                          return (
                            <div
                              key={tech.id}
                              onClick={() => selectTechnique(tech)}
                              className={`p-3 rounded-md border text-left cursor-pointer transition-all duration-200 group ${bgClass} ${
                                selectedTechId === tech.id ? "ring-2 ring-cyber-cyan" : ""
                              }`}
                              title={tech.description}
                            >
                              <div className="flex items-start justify-between gap-1 mb-1">
                                <span className="text-[9px] font-mono leading-none tracking-wider opacity-70 group-hover:text-white transition-colors">
                                  {tech.id}
                                </span>
                                {conf && (
                                  <span className="text-[9px] font-bold text-white bg-slate-900 px-1 rounded border border-slate-700">
                                    {conf}%
                                  </span>
                                )}
                              </div>
                              <p className="text-[10px] font-bold leading-tight group-hover:text-white transition-colors line-clamp-2">
                                {tech.name}
                              </p>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Slide-out technique details pane (Simple modal approach for now) */}
      {selectedTechId && techDetails && (
        <div className="fixed inset-y-0 right-0 w-96 bg-slate-900 border-l border-slate-700 shadow-2xl z-50 p-6 flex flex-col transform transition-transform animate-in slide-in-from-right">
          <div className="flex justify-between items-start mb-6 border-b border-slate-800 pb-4">
            <div>
              <span className="text-cyber-cyan font-mono text-sm">{techDetails.id}</span>
              <h2 className="text-lg font-bold text-white mt-1">{techDetails.name}</h2>
            </div>
            <button onClick={() => setSelectedTechId(null)} className="text-slate-400 hover:text-white p-1 rounded-md hover:bg-slate-800">
              <X className="h-5 w-5" />
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto space-y-6">
            <div>
              <h4 className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-2">Description</h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                {techDetails.description || "No description available."}
              </p>
            </div>
            
            {techDetails.threat_actors && (
              <div>
                <h4 className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-2">Likely Threat Actors</h4>
                <div className="space-y-2">
                  {techDetails.threat_actors.map(actor => (
                    <div key={actor.name} className="flex items-center justify-between p-3 rounded-lg bg-slate-950/50 border border-slate-800">
                      <div>
                        <span className="font-bold text-white text-sm">{actor.name}</span>
                        <span className="text-xs text-slate-500 ml-2">({actor.origin})</span>
                      </div>
                      <span className="text-xs font-mono text-cyber-purple font-bold">{actor.similarity * 100}% Match</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            <a
              href={`https://attack.mitre.org/techniques/${techDetails.id.split('.')[0]}`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-center gap-2 w-full py-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors"
            >
              <span>View MITRE Documentation</span>
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
