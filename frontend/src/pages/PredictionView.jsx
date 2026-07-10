import React, { useState, useEffect, useMemo } from "react";
import { 
  Radar, Activity, ShieldAlert, Crosshair, AlertTriangle, ChevronRight, Zap, TrendingUp
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Area, AreaChart
} from "recharts";
import ReactFlow, { Background, Controls, MarkerType } from "reactflow";
import "reactflow/dist/style.css";

import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import { api } from "../api/client";

const nodeStyle = {
  background: '#0f172a',
  color: '#cbd5e1',
  border: '1px solid #1e293b',
  borderRadius: '8px',
  padding: '12px',
  fontSize: '12px',
  fontFamily: 'monospace',
  boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.5)'
};

const currentStyle = {
  ...nodeStyle,
  border: '1px solid #3b82f6',
  boxShadow: '0 0 10px rgba(59, 130, 246, 0.5)'
};

const predictedStyle = {
  ...nodeStyle,
  border: '1px solid #f59e0b',
  background: '#291706',
  boxShadow: '0 0 15px rgba(245, 158, 11, 0.4)'
};

function FutureThreatSimulation({ currentTechnique, forecast }) {
  const { nodes, edges } = useMemo(() => {
    if (!currentTechnique || !forecast || forecast.length === 0) {
      return { nodes: [], edges: [] };
    }

    const n = [];
    const e = [];

    // Current Node
    n.push({
      id: "node-current",
      data: {
        label: (
          <div className="flex flex-col items-center">
            <span className="text-[10px] text-blue-400 font-bold mb-1">CURRENT POSITION</span>
            <strong className="text-white">{currentTechnique}</strong>
          </div>
        )
      },
      position: { x: 0, y: 150 },
      style: currentStyle,
      sourcePosition: 'right',
      targetPosition: 'left'
    });

    // Predicted Nodes
    forecast.forEach((stepObj, index) => {
      const nodeId = `node-pred-${index}`;
      n.push({
        id: nodeId,
        data: {
          label: (
            <div className="flex flex-col items-center">
              <span className="text-[10px] text-orange-400 font-bold mb-1">PREDICTED STEP {stepObj.step}</span>
              <strong className="text-white">{stepObj.technique_id}</strong>
              <span className="text-[10px] font-mono mt-1 text-orange-300">{stepObj.probability}% Prob</span>
            </div>
          )
        },
        position: { x: (index + 1) * 250, y: 150 + (index % 2 === 0 ? -30 : 30) },
        style: predictedStyle,
        sourcePosition: 'right',
        targetPosition: 'left'
      });

      const sourceId = index === 0 ? "node-current" : `node-pred-${index - 1}`;
      e.push({
        id: `edge-${sourceId}-${nodeId}`,
        source: sourceId,
        target: nodeId,
        animated: true,
        style: { stroke: '#f59e0b', strokeWidth: 2, strokeDasharray: '5 5' },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: '#f59e0b',
        },
      });
    });

    return { nodes: n, edges: e };
  }, [currentTechnique, forecast]);

  return (
    <div style={{ height: '100%', width: '100%' }}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background color="#1e293b" gap={16} />
        <Controls style={{ background: '#0f172a', border: '1px solid #1e293b', fill: '#cbd5e1' }} />
      </ReactFlow>
    </div>
  );
}

const DEMO_FORECAST = {
  current_technique: "T1068",
  expected_impact: "Ransomware / Data Exfiltration",
  forecast: [
    { step: 1, technique_id: "T1003 — Credential Dumping", probability: 91 },
    { step: 2, technique_id: "T1021 — Remote Services", probability: 84 },
    { step: 3, technique_id: "T1486 — Data Encrypted for Impact", probability: 76 },
    { step: 4, technique_id: "T1490 — Inhibit System Recovery", probability: 62 }
  ],
  recommended_actions: [
    "Isolate affected host immediately from OT network segment",
    "Rotate all privileged credentials and revoke active sessions",
    "Enable enhanced logging on lateral movement vectors (RDP, SMB)",
    "Deploy honeypot decoy assets in Internal IT segment",
    "Notify ICS-CERT and initiate incident playbook P-04"
  ]
};

export default function PredictionView() {
  const [loading, setLoading] = useState(true);
  const [highRisk, setHighRisk] = useState([]);
  const [forecastData, setForecastData] = useState(null);
  
  const fetchDashboardData = async () => {
    // Try to load high-risk entities from the anomaly endpoint
    try {
      const hr = await api.get("/api/v1/anomaly/high-risk");
      setHighRisk(Array.isArray(hr) ? hr : []);
    } catch (e) {
      console.warn("Could not load high-risk entities", e);
    }

    // Try to load next-actions prediction from predictions endpoint
    try {
      const data = await api.get("/api/predictions/next-actions");
      if (data && data.forecast && data.forecast.length > 0) {
        setForecastData(data);
      } else {
        setForecastData(DEMO_FORECAST);
      }
    } catch (e) {
      console.warn("Prediction API unavailable, using demo data", e);
      setForecastData(DEMO_FORECAST);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  if (loading) {
    return (
      <DashboardLayout title="Attack Prediction Engine">
        <LoadingState message="Initializing Predictive Models and Threat Forecaster..." />
      </DashboardLayout>
    );
  }

  // Generate data for risk escalation chart
  const riskChartData = [
    { time: "T-0", severity: 40, label: "Initial Access" },
    { time: "T+1", severity: 60, label: "Privilege Escalation" },
    { time: "T+2", severity: 85, label: "Credential Dumping" },
    { time: "T+3", severity: 95, label: "Lateral Movement" },
    { time: "T+4", severity: 100, label: "Ransomware" }
  ];

  return (
    <DashboardLayout title="Attack Prediction Engine">
      <div className="flex flex-col h-[calc(100vh-130px)] gap-6 overflow-y-auto pb-6">
        
        {/* Header Banner */}
        <div className="flex items-center justify-between p-5 rounded-xl bg-gradient-to-r from-orange-900/20 to-red-900/20 border border-orange-500/30 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/50 text-red-400">
              <Radar className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white uppercase font-mono tracking-wider">
                Predictive Threat Forecaster
              </h3>
              <p className="text-xs text-orange-200/70 mt-1 max-w-xl">
                Anticipating attacker movements using probabilistic transition graphs and MITRE ATT&CK heuristics.
              </p>
            </div>
          </div>
          {forecastData && (
            <div className="text-right flex flex-col items-end">
              <span className="text-[10px] text-orange-400/80 font-mono font-bold uppercase tracking-widest mb-1">
                Predicted Ultimate Impact
              </span>
              <div className="px-3 py-1 rounded bg-red-500/20 border border-red-500 text-red-100 font-bold text-sm shadow-[0_0_15px_rgba(239,68,68,0.3)]">
                {forecastData.expected_impact}
              </div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-[300px]">
          
          {/* Attack Forecast Panel */}
          <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-5 flex flex-col">
            <div className="flex items-center gap-2 mb-5 text-orange-400 border-b border-slate-800 pb-3">
              <Activity className="h-5 w-5" />
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Predicted Timeline</h3>
            </div>
            
            <div className="flex-1 space-y-4">
              {forecastData?.forecast ? forecastData.forecast.map((f, i) => (
                <div key={i} className="flex gap-4">
                  <div className="flex flex-col items-center">
                    <div className="h-8 w-8 rounded-full bg-slate-900 border border-orange-500/50 flex items-center justify-center text-xs font-bold text-orange-400">
                      {f.step}
                    </div>
                    {i !== forecastData.forecast.length - 1 && (
                      <div className="w-0.5 h-full bg-slate-800 my-1"></div>
                    )}
                  </div>
                  <div className="flex-1 pb-4">
                    <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                      <div className="flex justify-between items-start mb-1">
                        <span className="text-[11px] text-cyber-cyan font-mono font-bold">{f.technique_id}</span>
                        <span className="text-[10px] font-mono font-bold text-orange-400">{f.probability}% Probable</span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-1.5 mt-2">
                        <div className="bg-gradient-to-r from-orange-500 to-red-500 h-1.5 rounded-full" style={{ width: `${f.probability}%` }}></div>
                      </div>
                    </div>
                  </div>
                </div>
              )) : (
                <div className="text-center text-slate-500 font-mono text-xs mt-10">No forecast data</div>
              )}
            </div>
          </div>

          {/* Risk Escalation Graph */}
          <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-5 flex flex-col">
            <div className="flex items-center gap-2 mb-5 text-red-400 border-b border-slate-800 pb-3">
              <TrendingUp className="h-5 w-5" />
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Risk Escalation Curve</h3>
            </div>
            <div className="flex-1 w-full h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskChartData}>
                  <defs>
                    <linearGradient id="colorSeverity" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                  <RechartsTooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    itemStyle={{ color: '#ef4444', fontWeight: 'bold' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Area type="monotone" dataKey="severity" stroke="#ef4444" fillOpacity={1} fill="url(#colorSeverity)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recommended Actions */}
          <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-5 flex flex-col">
            <div className="flex items-center gap-2 mb-5 text-cyber-cyan border-b border-slate-800 pb-3">
              <ShieldAlert className="h-5 w-5" />
              <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Preemptive Actions</h3>
            </div>
            <div className="flex-1 space-y-3">
              {forecastData?.recommended_actions ? forecastData.recommended_actions.map((action, i) => (
                <div key={i} className="flex items-start gap-3 p-3 bg-slate-900/40 border border-slate-800 rounded-lg hover:bg-slate-900/80 transition-colors">
                  <Zap className="h-4 w-4 text-cyber-cyan mt-0.5 shrink-0" />
                  <span className="text-xs text-slate-300 leading-relaxed">{action}</span>
                </div>
              )) : (
                <div className="text-center text-slate-500 font-mono text-xs mt-10">No recommendations</div>
              )}
            </div>
          </div>
          
        </div>

        {/* Future Threat Simulation Visualization */}
        <div className="rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-5 flex flex-col min-h-[400px]">
          <div className="flex items-center gap-2 mb-4 text-purple-400">
            <Crosshair className="h-5 w-5" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono">Future Threat Simulation Graph</h3>
          </div>
          <div className="flex-1 border border-slate-800 rounded-lg overflow-hidden bg-slate-950/50">
            {forecastData ? (
              <FutureThreatSimulation 
                currentTechnique={forecastData.current_technique} 
                forecast={forecastData.forecast} 
              />
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500 font-mono text-xs">
                No active threat forecast available for simulation.
              </div>
            )}
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
}
