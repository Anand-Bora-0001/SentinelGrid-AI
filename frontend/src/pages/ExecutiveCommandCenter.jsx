import React from "react";
import { 
  ShieldAlert, 
  TrendingDown, 
  TrendingUp, 
  Activity, 
  Server,
  Zap,
  Target
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";

export default function ExecutiveCommandCenter() {
  return (
    <DashboardLayout title="Executive Command Center">
      <div className="space-y-6 max-w-6xl mx-auto">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <ShieldAlert className="h-8 w-8 text-red-500" />
              SentinelGrid Command Center
            </h1>
            <p className="text-slate-400 mt-2">Executive Business Impact & Risk Assessment</p>
          </div>
          <div className="px-4 py-2 bg-red-500/20 border border-red-500/50 rounded-lg flex items-center gap-3">
            <div className="h-3 w-3 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-400 font-bold uppercase tracking-widest text-sm">DEFCON 2</span>
          </div>
        </div>

        {/* Top Impact Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center text-center shadow-lg shadow-black/50 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-red-500" />
            <h3 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-2">Current Threat Level</h3>
            <div className="text-5xl font-black text-red-500 mb-1">HIGH</div>
            <p className="text-xs text-slate-500 mt-2">Active campaigns targeting CNI</p>
          </div>

          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center text-center shadow-lg shadow-black/50 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-orange-500" />
            <h3 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-2">Predicted Business Impact</h3>
            <div className="text-4xl font-black text-orange-500 mb-1">SEVERE</div>
            <p className="text-xs text-slate-500 mt-2">Potential operational downtime: 48h+</p>
          </div>

          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center text-center shadow-lg shadow-black/50 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-cyan-500" />
            <h3 className="text-slate-400 text-sm font-bold uppercase tracking-wider mb-2">Assets At Risk</h3>
            <div className="text-5xl font-black text-cyan-400 mb-1 flex items-center justify-center gap-2">
              <Server className="h-8 w-8 text-cyan-500/50" />
              12
            </div>
            <p className="text-xs text-slate-500 mt-2">Including 3 SCADA Controllers</p>
          </div>
        </div>

        {/* ROI / AI Impact Row */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
          <div className="p-8 rounded-xl bg-gradient-to-br from-indigo-950/50 to-slate-900 border border-indigo-500/30 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Target className="h-5 w-5 text-indigo-400" />
                <h3 className="text-indigo-300 text-sm font-bold uppercase tracking-wider">AI Detection Impact</h3>
              </div>
              <p className="text-slate-400 text-sm max-w-[250px]">Mean Time To Detect (MTTD) reduced from industry average of 14 days to seconds.</p>
            </div>
            <div className="text-right">
              <div className="flex items-center justify-end gap-2 text-emerald-400 mb-1">
                <TrendingDown className="h-6 w-6" />
                <span className="text-5xl font-black">87%</span>
              </div>
              <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Improvement</span>
            </div>
          </div>

          <div className="p-8 rounded-xl bg-gradient-to-br from-purple-950/50 to-slate-900 border border-purple-500/30 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Zap className="h-5 w-5 text-purple-400" />
                <h3 className="text-purple-300 text-sm font-bold uppercase tracking-wider">AI Response Impact</h3>
              </div>
              <p className="text-slate-400 text-sm max-w-[250px]">Mean Time To Respond (MTTR) reduced from hours to automated playbook simulation.</p>
            </div>
            <div className="text-right">
              <div className="flex items-center justify-end gap-2 text-emerald-400 mb-1">
                <TrendingDown className="h-6 w-6" />
                <span className="text-5xl font-black">74%</span>
              </div>
              <span className="text-xs text-slate-500 font-bold uppercase tracking-widest">Improvement</span>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
