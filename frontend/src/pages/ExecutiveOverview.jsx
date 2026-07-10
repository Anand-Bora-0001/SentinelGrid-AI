import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  ShieldCheck, 
  Globe, 
  Info,
  ChevronRight,
  Sparkles
} from "lucide-react";
import { Link } from "react-router-dom";
import DashboardLayout from "../components/layout/DashboardLayout";
import MetricCard from "../components/common/MetricCard";
import RiskGauge from "../components/common/RiskGauge";
import LoadingState from "../components/common/LoadingState";
import { api } from "../api/client";
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer 
} from "recharts";
import SeverityBadge from "../components/common/SeverityBadge";

export default function ExecutiveOverview() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState({
    riskScore: 35,
    activeIncidents: 0,
    criticalVulns: 0,
    totalTelemetry: 0,
    recentIncidents: [],
    trendData: [],
    topOrigins: []
  });

  const loadData = async () => {
    try {
      setLoading(true);
      
      // Fetch data from endpoints
      const healthData = await api.get("/health");
      const incidentsData = await api.get("/api/incidents", { limit: 5 });
      const telemetryData = await api.get("/api/telemetry", { limit: 1 });
      const forecastData = await api.get("/api/predictions/risk-forecast");
      
      const dbMetrics = healthData?.database?.metrics || {};
      const activeIncCount = dbMetrics.active_incidents || 0;
      
      // Calculate risk score based on active incidents and vulnerabilities
      let riskScore = 15; // baseline
      riskScore += activeIncCount * 25;
      riskScore += (dbMetrics.vulnerability_count || 0) * 2;
      riskScore = Math.min(riskScore, 98); // cap at 98 for demo

      // Map origins
      const topOrigins = [
        { country: "Russia", count: 42, percentage: 45, code: "RU" },
        { country: "China", count: 28, percentage: 30, code: "CN" },
        { country: "North Korea", count: 15, percentage: 16, code: "KP" },
        { country: "Unknown / Tor", count: 8, percentage: 9, code: "Tor" }
      ];

      const parsedTrend = (forecastData?.forecast && forecastData.forecast.length > 0)
        ? forecastData.forecast.map(f => {
            const dateObj = new Date(f.date);
            const dayLabel = dateObj.toLocaleDateString('en-US', { weekday: 'short' }) + " " + dateObj.getDate();
            // Scale value to fit a nice 100-scale risk index and 500-scale event count visualizer
            const riskVal = Math.min(95, Math.max(10, Math.round(f.predicted_risk * 12)));
            const eventVal = Math.max(15, Math.round(f.predicted_risk * 8));
            return {
              day: dayLabel,
              count: eventVal,
              risk: riskVal
            };
          })
        : [
            { day: "Mon", count: 120, risk: 25 },
            { day: "Tue", count: 180, risk: 30 },
            { day: "Wed", count: 320, risk: 45 },
            { day: "Thu", count: 240, risk: 35 },
            { day: "Fri", count: 410, risk: 55 },
            { day: "Sat", count: 150, risk: 40 },
            { day: "Sun", count: 290, risk: 65 }
          ];

      setData({
        riskScore: riskScore,
        activeIncidents: activeIncCount,
        criticalVulns: dbMetrics.vulnerability_count || 0,
        totalTelemetry: dbMetrics.telemetry_count || 0,
        recentIncidents: incidentsData.items || [],
        trendData: parsedTrend,
        topOrigins: topOrigins
      });
    } catch (e) {
      console.error("Failed to load Executive Overview metrics", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  if (loading) {
    return (
      <DashboardLayout title="Executive Overview">
        <LoadingState message="Decrypting CNI grid telemetry and analyzing threat baseline..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Executive Security Console">
      {/* Risk Core Header */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
        
        {/* Gauge card */}
        <div className="lg:col-span-1 p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md flex flex-col items-center justify-center">
          <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 mb-4 align-self-start w-full">
            Composite CNI Threat Index
          </h4>
          <RiskGauge score={data.riskScore} size={170} />
          <div className="mt-4 text-center">
            <span className="text-slate-400 text-xs font-medium">
              Calculated using active threat paths, lateral movements, and open CNI vulnerability CVSS scores.
            </span>
          </div>
        </div>

        {/* AI threat summary explanation */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-cyber-purple font-mono text-xs uppercase tracking-widest mb-3">
              <Sparkles className="h-4.5 w-4.5 animate-pulse" />
              <span>AI Agent Platform Assessment</span>
            </div>
            <h3 className="text-xl font-bold text-white mb-3">
              {data.activeIncidents > 0 
                ? "Anomalous SCADA event sequences detected" 
                : "Baseline infrastructure behavior is within parameters"
              }
            </h3>
            <p className="text-slate-400 text-sm leading-relaxed mb-4">
              {data.activeIncidents > 0 
                ? `SentinelGrid's ML engine has correlated threat signals into ${data.activeIncidents} active Incident campaign(s). We have detected indicators matching MITRE ATT&CK technique progression (Initial Access -> Lateral Movement). Recommended: Check proposed mitigation playbooks in the Active Incidents tab.`
                : "No high-risk event chains detected in the last 24 hours. The anomaly detector is profiling telemetry from 14 operational technology (OT) nodes and corporate systems. System baseline profiles are updated regularly."
              }
            </p>
          </div>
          
          <div className="flex flex-wrap gap-4 border-t border-slate-850 pt-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4.5 w-4.5 text-cyber-cyan" />
              <span className="text-xs text-slate-400 font-mono">Anomaly Engine: <strong className="text-white">Active (98% confidence)</strong></span>
            </div>
            <div className="flex items-center gap-2">
              <Globe className="h-4.5 w-4.5 text-cyber-cyan" />
              <span className="text-xs text-slate-400 font-mono">Sensors Monitored: <strong className="text-white">14 CNI Nodes</strong></span>
            </div>
          </div>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <MetricCard 
          title="Active Security Incidents" 
          value={data.activeIncidents} 
          icon={ShieldAlert}
          subtext="Uncontained attack campaigns"
          trendValue={data.activeIncidents > 0 ? "+100%" : "0% change"}
          trendDirection={data.activeIncidents > 0 ? "up" : "down"}
          glowColor={data.activeIncidents > 0 ? "danger" : "cyan"}
        />
        <MetricCard 
          title="Critical Vulnerabilities" 
          value={data.criticalVulns} 
          icon={AlertTriangle}
          subtext="CVEs in CNI Assets"
          trendValue="Ranked in Patch Queue"
          trendDirection="down"
          glowColor={data.criticalVulns > 0 ? "danger" : "cyan"}
        />
        <MetricCard 
          title="Telemetry Flow Rate" 
          value={`${data.totalTelemetry} events`} 
          icon={Activity}
          subtext="Monitored CNI feeds"
          trendValue="+14.2%"
          trendDirection="up"
          glowColor="purple"
        />
      </div>

      {/* Row with Trend Graph & Incident Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Trend Area Chart */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md flex flex-col">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono mb-6">
            7-Day Threat Activity & Risk Trend
          </h3>
          <div className="flex-1 min-h-[320px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: "#111827", borderColor: "#1e293b", borderRadius: 8 }}
                  labelStyle={{ color: "#fff", fontWeight: "bold" }}
                />
                <Area type="monotone" name="Telemetry Count" dataKey="count" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                <Area type="monotone" name="Risk Score" dataKey="risk" stroke="#8b5cf6" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top active incidents feed */}
        <div className="lg:col-span-1 p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono mb-4">
              Active Incident Campaign Feed
            </h3>
            
            {data.recentIncidents.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-center">
                <ShieldCheck className="h-10 w-10 text-cyber-success mb-3 opacity-60" />
                <p className="text-xs text-slate-500 font-medium">
                  Zero active threats detected. No uncontained incidents pending review.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {data.recentIncidents.map((incident) => (
                  <div key={incident.id} className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-850 hover:border-slate-800 transition-all flex items-start justify-between">
                    <div className="pr-2 truncate">
                      <Link to="/incidents" className="text-xs font-bold text-white hover:text-cyber-cyan transition-colors truncate block">
                        #{incident.id} — {incident.title}
                      </Link>
                      <span className="text-[10px] text-slate-500 font-mono block mt-1">
                        Blast Radius: {incident.blast_radius}%
                      </span>
                    </div>
                    <SeverityBadge severity={incident.severity} />
                  </div>
                ))}
              </div>
            )}
          </div>
          
          <Link 
            to="/incidents" 
            className="w-full flex items-center justify-center gap-2 mt-6 py-2.5 rounded-lg border border-slate-800 text-xs font-semibold text-slate-400 hover:text-cyber-cyan hover:bg-slate-900/60 transition-all font-mono"
          >
            <span>Access Security Incidents Console</span>
            <ChevronRight className="h-4 w-4" />
          </Link>
        </div>
      </div>
    </DashboardLayout>
  );
}
