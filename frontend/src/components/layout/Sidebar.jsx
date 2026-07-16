import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Globe,
  ShieldAlert,
  Grid,
  AlertTriangle,
  BrainCircuit,
  Cpu,
  History,
  Terminal,
  UserCheck,
  MessageSquare,
  Activity,
  LogOut,
  Trash2
} from "lucide-react";
import { api } from "../../api/client";

export default function Sidebar() {
  const location = useLocation();
  const currentPath = location.pathname;

  const menuItems = [
    { name: "Executive Command Center", path: "/command-center", icon: Activity },
    { name: "Executive Overview", path: "/", icon: LayoutDashboard },
    { name: "Threat Map", path: "/threat-map", icon: Globe },
    { name: "Active Incidents", path: "/incidents", icon: ShieldAlert },
    { name: "MITRE ATT&CK Matrix", path: "/mitre", icon: Grid },
    { name: "CNI Patch Prioritization", path: "/vulnerabilities", icon: AlertTriangle },
    { name: "Attack Predictions", path: "/predictions", icon: BrainCircuit },
    { name: "Cyber Digital Twin", path: "/digital-twin", icon: Cpu },
    { name: "UEBA Analytics", path: "/ueba", icon: UserCheck },
    { name: "Threat Intelligence", path: "/threat-intel", icon: MessageSquare },
    { name: "Audit Trail & Logs", path: "/audit", icon: History },
    { name: "Recycle Bin", path: "/recycle-bin", icon: Trash2 },
  ];

  const handleLogout = () => {
    api.clearAuth();
    window.location.href = "/login";
  };

  return (
    <aside className="w-64 glass-panel border-r border-slate-800 flex flex-col h-full z-20">
      {/* Platform Branding */}
      <div className="p-6 border-b border-slate-800/80 flex items-center gap-3">
        <Terminal className="h-6 w-6 text-cyber-cyan animate-pulse" />
        <div>
          <h1 className="text-lg font-bold tracking-tight text-white m-0 leading-none">
            SENTINEL<span className="text-cyber-cyan font-mono">GRID</span>
          </h1>
          <span className="text-[10px] text-cyber-purple font-mono uppercase tracking-widest block mt-1">
            CNI Resilience AI
          </span>
        </div>
      </div>

      {/* Navigation Menu */}
      <nav className="flex-1 px-4 py-6 space-y-1.5 overflow-y-auto">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentPath === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 border group ${
                isActive
                  ? "bg-cyber-cyan/10 border-cyber-cyan text-cyber-cyan shadow-md"
                  : "border-transparent text-slate-400 hover:text-white hover:bg-slate-800/40 hover:border-slate-800"
              }`}
            >
              <Icon className={`h-4.5 w-4.5 transition-transform duration-300 group-hover:scale-110 ${
                isActive ? "text-cyber-cyan" : "text-slate-400 group-hover:text-cyber-cyan"
              }`} />
              <span className="truncate">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Bottom User / Session Section */}
      <div className="p-4 border-t border-slate-800/80">
        <div className="flex items-center justify-between px-2 py-3 rounded-lg bg-slate-900/60 border border-slate-800/50 mb-2">
          <div className="truncate pr-2">
            <p className="text-xs font-semibold text-white truncate leading-none mb-1">
              {api.getUser() || "Operator"}
            </p>
            <span className="text-[10px] text-cyber-cyan font-mono uppercase tracking-wider">
              {api.getRole() === "admin" ? "Administrator" : (api.getRole()?.replace("_", " ") || "SOC Analyst")}
            </span>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-transparent hover:border-red-500/20 transition-all duration-200"
        >
          <LogOut className="h-4 w-4" />
          Sign Out Platform
        </button>
      </div>
    </aside>
  );
}
