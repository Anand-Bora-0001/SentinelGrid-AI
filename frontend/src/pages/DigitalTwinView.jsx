import React, { useState, useEffect, useMemo, useCallback } from "react";
import { 
  Network, Server, Shield, Database, Activity, Target, Zap, AlertTriangle, Layers, Info
} from "lucide-react";
import ReactFlow, { 
  Background, Controls, MarkerType, useNodesState, useEdgesState, Handle, Position
} from "reactflow";
import "reactflow/dist/style.css";

import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import { api } from "../api/client";

// --- Custom Node Component for Infrastructure Assets ---
const CustomAssetNode = ({ data }) => {
  let borderColor = "#334155";
  let bgColor = "#0f172a";
  let pulse = false;
  let glowColor = "transparent";

  // Status-based coloring
  if (data.status === "compromised") {
    borderColor = "#ef4444"; // Red
    bgColor = "#450a0a";
    pulse = true;
    glowColor = "rgba(239,68,68,0.5)";
  } else if (data.status === "at_risk" || data.status === "predicted") {
    borderColor = "#f59e0b"; // Orange/Yellow
    bgColor = "#451a03";
    pulse = true;
    glowColor = "rgba(245,158,11,0.5)";
  } else if (data.status === "vulnerable") {
    borderColor = "#eab308"; // Yellow
    bgColor = "#422006";
  } else {
    borderColor = "#10b981"; // Green (Safe)
  }

  const IconComponent = () => {
    switch(data.type) {
      case "Firewall": return <Shield className="h-5 w-5" />;
      case "Web Server": return <Activity className="h-5 w-5" />;
      case "Database": return <Database className="h-5 w-5" />;
      case "SCADA Server":
      case "PLC": return <Zap className="h-5 w-5" />;
      case "Internet": return <Network className="h-5 w-5" />;
      default: return <Server className="h-5 w-5" />;
    }
  };

  return (
    <div 
      className={`relative rounded-lg p-3 w-40 flex flex-col items-center justify-center border-2 transition-all duration-500`}
      style={{ 
        borderColor, 
        backgroundColor: bgColor,
        boxShadow: `0 0 15px ${glowColor}`,
        animation: pulse ? 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite' : 'none'
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="text-white mb-2" style={{ color: borderColor }}>
        <IconComponent />
      </div>
      <div className="text-white font-bold text-xs font-mono text-center mb-1">{data.name}</div>
      <div className="text-[9px] text-slate-400 font-mono text-center uppercase tracking-wider">{data.type}</div>
      {data.status && data.status !== "safe" && (
        <div className="absolute -top-2 -right-2 bg-slate-900 rounded-full p-1 border" style={{ borderColor }}>
          <AlertTriangle className="h-3 w-3" style={{ color: borderColor }} />
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
};

const nodeTypes = {
  assetNode: CustomAssetNode
};

export default function DigitalTwinView() {
  const [loading, setLoading] = useState(true);
  const [topology, setTopology] = useState(null);
  const [simulation, setSimulation] = useState(null);
  
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  const [selectedAsset, setSelectedAsset] = useState(null);

  const [visibleStatuses, setVisibleStatuses] = useState({
    safe: true,
    compromised: true,
    predicted: true,
    vulnerable: true
  });

  const toggleStatus = (status) => {
    setVisibleStatuses(prev => ({
      ...prev,
      [status]: !prev[status]
    }));
  };

  const DEMO_TOPOLOGY = {
    nodes: [
      { id: "internet", name: "Internet Gateway", type: "Internet", segment: "External", criticality: 30, status: "safe" },
      { id: "fw-perimeter", name: "Perimeter Firewall", type: "Firewall", segment: "External", criticality: 90, status: "safe" },
      { id: "web-01", name: "Web Server 01", type: "Web Server", segment: "DMZ", criticality: 75, status: "safe" },
      { id: "web-02", name: "Web Server 02", type: "Web Server", segment: "DMZ", criticality: 70, status: "safe" },
      { id: "fw-internal", name: "Internal Firewall", type: "Firewall", segment: "DMZ", criticality: 95, status: "safe" },
      { id: "app-01", name: "App Server", type: "Server", segment: "Internal IT", criticality: 80, status: "safe" },
      { id: "db-01", name: "Core Database", type: "Database", segment: "Internal IT", criticality: 95, status: "safe" },
      { id: "ad-01", name: "Active Directory", type: "Server", segment: "Internal IT", criticality: 99, status: "safe" },
      { id: "scada-gw", name: "SCADA Gateway", type: "SCADA Server", segment: "OT / SCADA", criticality: 100, status: "safe" },
      { id: "plc-01", name: "PLC Controller 01", type: "PLC", segment: "OT / SCADA", criticality: 100, status: "safe" },
      { id: "plc-02", name: "PLC Controller 02", type: "PLC", segment: "OT / SCADA", criticality: 100, status: "safe" },
    ],
    edges: [
      { id: "e1", source: "internet", target: "fw-perimeter", type: "network_flow" },
      { id: "e2", source: "fw-perimeter", target: "web-01", type: "network_flow" },
      { id: "e3", source: "fw-perimeter", target: "web-02", type: "network_flow" },
      { id: "e4", source: "web-01", target: "fw-internal", type: "network_flow" },
      { id: "e5", source: "web-02", target: "fw-internal", type: "network_flow" },
      { id: "e6", source: "fw-internal", target: "app-01", type: "network_flow" },
      { id: "e7", source: "app-01", target: "db-01", type: "db_query" },
      { id: "e8", source: "app-01", target: "ad-01", type: "auth_flow" },
      { id: "e9", source: "ad-01", target: "scada-gw", type: "auth_flow" },
      { id: "e10", source: "scada-gw", target: "plc-01", type: "scada_cmd" },
      { id: "e11", source: "scada-gw", target: "plc-02", type: "scada_cmd" },
    ]
  };

  const DEMO_SIMULATION = {
    current_asset: "web-01",
    predicted_assets: ["fw-internal", "app-01"],
    affected_assets: ["db-01", "ad-01", "scada-gw"],
    predicted_path: ["internet", "fw-perimeter", "web-01", "fw-internal", "app-01", "ad-01", "scada-gw", "plc-01"],
    blast_radius_severity: "CRITICAL",
    mitre_mapping: {
      "web-01": "T1190 — Exploit Public Facing Application",
      "fw-internal": "T1021 — Remote Services",
      "app-01": "T1068 — Exploitation for Privilege Escalation",
      "ad-01": "T1003 — OS Credential Dumping",
      "scada-gw": "T1486 — Data Encrypted for Impact"
    }
  };

  const fetchTwinData = async () => {
    try {
      const data = await api.get("/api/v1/digital-twin/predicted-path");
      if (data && data.topology && data.topology.nodes && data.topology.nodes.length > 0) {
        setTopology(data.topology);
        setSimulation(data.simulation);
      } else {
        // Use demo data if API returns empty response
        setTopology(DEMO_TOPOLOGY);
        setSimulation(DEMO_SIMULATION);
      }
    } catch (e) {
      console.warn("Digital Twin API unavailable, using demo topology", e);
      setTopology(DEMO_TOPOLOGY);
      setSimulation(DEMO_SIMULATION);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTwinData();
    // In a real SOC, we'd poll or use websockets here
    // const interval = setInterval(fetchTwinData, 10000);
    // return () => clearInterval(interval);
  }, []);

  // Compute Layout (simple left-to-right based on segments for the demo)
  useEffect(() => {
    if (!topology) return;

    const segmentOrder = ["External", "DMZ", "Internal IT", "OT / SCADA"];
    const yOffsets = { "External": 0, "DMZ": 0, "Internal IT": 0, "OT / SCADA": 0 };

    const initialNodes = topology.nodes.map(node => {
      // Determine segment index for X axis
      const xIdx = segmentOrder.indexOf(node.segment) !== -1 ? segmentOrder.indexOf(node.segment) : 0;
      
      // Calculate Y axis to stack nodes in the same segment
      const currentY = yOffsets[node.segment] || 0;
      yOffsets[node.segment] = currentY + 120;

      // Check status from simulation if available
      let currentStatus = node.status || "safe";
      if (simulation) {
        if (node.id === simulation.current_asset) {
          currentStatus = "compromised";
        } else if (simulation.predicted_assets.includes(node.id)) {
          currentStatus = "predicted";
        } else if (simulation.affected_assets.includes(node.id)) {
          currentStatus = "vulnerable";
        }
      }

      const isVisible = visibleStatuses[currentStatus];

      return {
        id: node.id,
        type: 'assetNode',
        position: { x: xIdx * 300 + 50, y: currentY + 100 },
        style: { opacity: isVisible ? 1 : 0.15, transition: 'opacity 0.3s ease' },
        data: { 
          ...node, 
          status: currentStatus,
          onSelect: () => setSelectedAsset(node)
        }
      };
    });

    const initialEdges = topology.edges.map(edge => {
      // Animate edge if it's part of the predicted path
      let isAnimated = false;
      let strokeColor = "#334155";
      
      if (simulation && simulation.predicted_path) {
        const path = simulation.predicted_path;
        const sIdx = path.indexOf(edge.source);
        const tIdx = path.indexOf(edge.target);
        
        // If both nodes are in path and sequential, animate the edge
        if (sIdx !== -1 && tIdx !== -1 && tIdx === sIdx + 1) {
          isAnimated = true;
          // If source is current_asset or before, it's a compromised path (red)
          const currentIdx = path.indexOf(simulation.current_asset);
          if (sIdx <= currentIdx) {
            strokeColor = "#ef4444";
          } else {
            // Predicted future path (orange)
            strokeColor = "#f59e0b";
          }
        }
      }

      // Map node statuses to check if edge should be visible
      let sourceStatus = "safe";
      let targetStatus = "safe";
      if (simulation) {
        if (edge.source === simulation.current_asset) sourceStatus = "compromised";
        else if (simulation.predicted_assets.includes(edge.source)) sourceStatus = "predicted";
        else if (simulation.affected_assets.includes(edge.source)) sourceStatus = "vulnerable";
        
        if (edge.target === simulation.current_asset) targetStatus = "compromised";
        else if (simulation.predicted_assets.includes(edge.target)) targetStatus = "predicted";
        else if (simulation.affected_assets.includes(edge.target)) targetStatus = "vulnerable";
      }

      const edgeVisible = visibleStatuses[sourceStatus] && visibleStatuses[targetStatus];

      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: isAnimated && edgeVisible,
        style: { stroke: strokeColor, strokeWidth: isAnimated ? 3 : 1, opacity: edgeVisible ? 1 : 0.15, transition: 'opacity 0.3s ease' },
        markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor },
        label: edge.type.replace("_", " "),
        labelStyle: { fill: "#94a3b8", fontSize: 10, fontFamily: "monospace", opacity: edgeVisible ? 1 : 0.15 },
        labelBgStyle: { fill: "#0f172a", fillOpacity: 0.8 }
      };
    });

    setNodes(initialNodes);
    setEdges(initialEdges);
    
    // Auto-select current asset if simulation active
    if (simulation && simulation.current_asset) {
      const activeNode = topology.nodes.find(n => n.id === simulation.current_asset);
      if (activeNode) setSelectedAsset(activeNode);
    }
  }, [topology, simulation, visibleStatuses, setNodes, setEdges]);

  const onNodeClick = useCallback((event, node) => {
    if (!topology) return;
    setSelectedAsset(topology.nodes.find(n => n.id === node.id));
  }, [topology]);

  if (loading) {
    return (
      <DashboardLayout title="Cyber Resilience Digital Twin">
        <LoadingState message="Constructing physical and logical topology map..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Cyber Resilience Digital Twin">
      <div className="flex flex-col h-[calc(100vh-130px)] gap-6 overflow-hidden">
        
        {/* Header Statistics Overlay */}
        <div className="flex shrink-0 items-center justify-between p-4 rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-md z-10">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-blue-950/50 border border-blue-500/30 text-blue-400">
                <Network className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white uppercase font-mono tracking-wider">
                  Live Infrastructure Topology
                </h3>
                <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                  <span className="text-blue-400">{topology?.nodes?.length || 0}</span> Assets Monitored • <span className="text-blue-400">{topology?.edges?.length || 0}</span> Logical Edges
                </div>
              </div>
            </div>
          </div>
          
          {simulation && simulation.current_asset && (
            <div className="flex items-center gap-6 border-l border-slate-800 pl-6">
              <div>
                <span className="text-[9px] text-slate-500 font-mono uppercase block mb-1">Blast Radius Exposure</span>
                <div className={`px-3 py-1 rounded text-xs font-bold font-mono text-white ${
                  simulation.blast_radius_severity === 'CRITICAL' ? 'bg-red-500/20 border border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.3)]' :
                  simulation.blast_radius_severity === 'HIGH' ? 'bg-orange-500/20 border border-orange-500' :
                  'bg-yellow-500/20 border border-yellow-500'
                }`}>
                  {simulation.blast_radius_severity}
                </div>
              </div>
              <div>
                <span className="text-[9px] text-slate-500 font-mono uppercase block mb-1">Assets Compromised</span>
                <div className="text-lg font-bold text-red-400 font-mono">
                  {simulation.predicted_path.indexOf(simulation.current_asset) + 1}
                </div>
              </div>
              <div>
                <span className="text-[9px] text-slate-500 font-mono uppercase block mb-1">Assets At Risk</span>
                <div className="text-lg font-bold text-orange-400 font-mono">
                  {simulation.affected_assets.length}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Main Workspace Area */}
        <div className="flex-1 flex gap-6 min-h-0 relative">
          
          {/* ReactFlow Canvas */}
          <div className="flex-1 rounded-xl bg-slate-950/80 border border-slate-800 overflow-hidden relative">
            <ReactFlow 
              nodes={nodes} 
              edges={edges} 
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={onNodeClick}
              nodeTypes={nodeTypes}
              fitView
              attributionPosition="bottom-right"
            >
              <Background color="#1e293b" gap={20} size={1} />
              <Controls position="top-left" style={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fill: '#cbd5e1' }} />
            </ReactFlow>

            {/* Legend Overlay */}
            <div className="absolute bottom-4 left-4 bg-slate-900/90 border border-slate-800 p-3 rounded-lg backdrop-blur text-[10px] font-mono text-slate-400 space-y-2 z-10 shadow-lg shadow-black/40 select-none">
              <div className="font-bold text-white mb-2 uppercase border-b border-slate-700 pb-1">Legend</div>
              
              <button 
                onClick={() => toggleStatus('safe')}
                className="flex items-center gap-2 w-full text-left transition-colors duration-150 hover:text-white"
              >
                <div 
                  className={`w-3.5 h-3.5 rounded-sm transition-all duration-200 ${
                    visibleStatuses.safe 
                      ? "bg-[#10b981] border border-[#10b981] shadow-[0_0_6px_rgba(16,185,129,0.4)]" 
                      : "bg-transparent border border-slate-650"
                  }`}
                ></div>
                <span className={visibleStatuses.safe ? "text-slate-200" : "text-slate-500 line-through"}>Safe</span>
              </button>

              <button 
                onClick={() => toggleStatus('compromised')}
                className="flex items-center gap-2 w-full text-left transition-colors duration-150 hover:text-white"
              >
                <div 
                  className={`w-3.5 h-3.5 rounded-sm transition-all duration-200 ${
                    visibleStatuses.compromised 
                      ? "bg-[#ef4444] border border-[#ef4444] shadow-[0_0_6px_rgba(239,68,68,0.4)]" 
                      : "bg-transparent border border-slate-650"
                  }`}
                ></div>
                <span className={visibleStatuses.compromised ? "text-slate-200" : "text-slate-500 line-through"}>Compromised</span>
              </button>

              <button 
                onClick={() => toggleStatus('predicted')}
                className="flex items-center gap-2 w-full text-left transition-colors duration-150 hover:text-white"
              >
                <div 
                  className={`w-3.5 h-3.5 rounded-sm transition-all duration-200 ${
                    visibleStatuses.predicted 
                      ? "bg-[#f59e0b] border border-[#f59e0b] shadow-[0_0_6px_rgba(245,158,11,0.4)]" 
                      : "bg-transparent border border-slate-650"
                  }`}
                ></div>
                <span className={visibleStatuses.predicted ? "text-slate-200" : "text-slate-500 line-through"}>Predicted Next</span>
              </button>

              <button 
                onClick={() => toggleStatus('vulnerable')}
                className="flex items-center gap-2 w-full text-left transition-colors duration-150 hover:text-white"
              >
                <div 
                  className={`w-3.5 h-3.5 rounded-sm transition-all duration-200 ${
                    visibleStatuses.vulnerable 
                      ? "bg-[#eab308] border border-[#eab308] shadow-[0_0_6px_rgba(234,179,8,0.4)]" 
                      : "bg-transparent border border-slate-650"
                  }`}
                ></div>
                <span className={visibleStatuses.vulnerable ? "text-slate-200" : "text-slate-500 line-through"}>In Blast Radius</span>
              </button>
            </div>
          </div>

          {/* Right Sidebar - Asset Explorer */}
          <div className="w-80 shrink-0 flex flex-col gap-4">
            
            {selectedAsset ? (
              <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-5 flex flex-col h-full animate-in slide-in-from-right-4">
                <div className="flex items-center gap-3 mb-4 border-b border-slate-800 pb-4">
                  <div className="p-2 rounded bg-slate-900 border border-slate-700 text-white">
                    <Server className="h-6 w-6" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono">{selectedAsset.name}</h3>
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider">{selectedAsset.type}</span>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto pr-1 space-y-6">
                  
                  {/* Status Block */}
                  <div>
                    <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-2 block">Current State</span>
                    {simulation && simulation.current_asset === selectedAsset.id ? (
                      <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/50 flex items-start gap-3">
                        <AlertTriangle className="h-4 w-4 text-red-500 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-bold text-red-400 uppercase">Compromised</div>
                          <div className="text-[10px] text-red-300 mt-1">Asset is actively compromised by adversary.</div>
                          {simulation.mitre_mapping && simulation.mitre_mapping[selectedAsset.id] && (
                            <div className="mt-2 text-[10px] bg-red-900/50 px-2 py-1 rounded inline-block text-white font-mono">
                              Active Technique: {simulation.mitre_mapping[selectedAsset.id]}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : simulation && simulation.predicted_assets.includes(selectedAsset.id) ? (
                      <div className="p-3 rounded-lg bg-orange-950/30 border border-orange-500/50 flex items-start gap-3">
                        <Target className="h-4 w-4 text-orange-500 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-bold text-orange-400 uppercase">Predicted Target</div>
                          <div className="text-[10px] text-orange-300 mt-1">High probability of adversary lateral movement to this asset.</div>
                          {simulation.mitre_mapping && simulation.mitre_mapping[selectedAsset.id] && (
                            <div className="mt-2 text-[10px] bg-orange-900/50 px-2 py-1 rounded inline-block text-white font-mono">
                              Predicted Technique: {simulation.mitre_mapping[selectedAsset.id]}
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/50 flex items-start gap-3">
                        <Shield className="h-4 w-4 text-emerald-500 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-bold text-emerald-400 uppercase">Nominal</div>
                          <div className="text-[10px] text-emerald-300 mt-1">No anomalous activity detected.</div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Details Block */}
                  <div>
                    <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-2 block">Asset Meta</span>
                    <div className="space-y-2">
                      <div className="flex justify-between p-2 rounded bg-slate-900/50 border border-slate-800 text-xs">
                        <span className="text-slate-400 font-mono">Segment</span>
                        <span className="text-white font-mono">{selectedAsset.segment}</span>
                      </div>
                      <div className="flex justify-between p-2 rounded bg-slate-900/50 border border-slate-800 text-xs">
                        <span className="text-slate-400 font-mono">Asset ID</span>
                        <span className="text-cyber-cyan font-mono">{selectedAsset.id}</span>
                      </div>
                      <div className="flex justify-between p-2 rounded bg-slate-900/50 border border-slate-800 text-xs items-center">
                        <span className="text-slate-400 font-mono">Criticality</span>
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                            <div 
                              className={`h-full ${selectedAsset.criticality > 80 ? 'bg-red-500' : selectedAsset.criticality > 50 ? 'bg-orange-500' : 'bg-blue-500'}`} 
                              style={{ width: `${selectedAsset.criticality}%` }}
                            ></div>
                          </div>
                          <span className="text-white font-mono font-bold">{selectedAsset.criticality}/100</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Actions Block */}
                  <div>
                    <span className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-2 block">Orchestration</span>
                    <div className="space-y-2">
                      <button className="w-full py-2 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono transition-colors">
                        Isolate Node from Segment
                      </button>
                      <button className="w-full py-2 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono transition-colors">
                        Initiate Memory Dump
                      </button>
                    </div>
                  </div>

                </div>
              </div>
            ) : (
              <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-6 flex flex-col items-center justify-center h-full text-center">
                <Layers className="h-10 w-10 text-slate-600 mb-4" />
                <h3 className="text-sm font-bold text-slate-300 font-mono uppercase tracking-wider mb-2">Asset Explorer</h3>
                <p className="text-xs text-slate-500 leading-relaxed">
                  Select an infrastructure node on the topological map to view real-time state, blast radius exposure, and predicted threats.
                </p>
              </div>
            )}
            
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
}
