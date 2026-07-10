/**
 * SentinelGrid AI — Shared Constants
 */

export const SEVERITY_LEVELS = {
  CRITICAL: {
    label: "CRITICAL",
    bg: "bg-red-950/40 text-red-400 border-red-800/60",
    text: "text-red-400",
    fill: "#ef4444",
    border: "border-red-500",
  },
  HIGH: {
    label: "HIGH",
    bg: "bg-orange-950/40 text-orange-400 border-orange-800/60",
    text: "text-orange-400",
    fill: "#f97316",
    border: "border-orange-500",
  },
  MEDIUM: {
    label: "MEDIUM",
    bg: "bg-yellow-950/40 text-yellow-400 border-yellow-800/60",
    text: "text-yellow-400",
    fill: "#eab308",
    border: "border-yellow-500",
  },
  LOW: {
    label: "LOW",
    bg: "bg-green-950/40 text-green-400 border-green-800/60",
    text: "text-green-400",
    fill: "#22c55e",
    border: "border-green-500",
  },
  INFO: {
    label: "INFO",
    bg: "bg-cyan-950/40 text-cyan-400 border-cyan-800/60",
    text: "text-cyan-400",
    fill: "#06b6d4",
    border: "border-cyan-500",
  }
};

export const INCIDENT_STATUS = {
  new: { label: "New", bg: "bg-blue-950/40 text-blue-400 border-blue-800/60" },
  investigating: { label: "Investigating", bg: "bg-purple-950/40 text-purple-400 border-purple-800/60" },
  contained: { label: "Contained", bg: "bg-orange-950/40 text-orange-400 border-orange-800/60" },
  resolved: { label: "Resolved", bg: "bg-green-950/40 text-green-400 border-green-800/60" },
  closed: { label: "Closed", bg: "bg-slate-900 text-slate-400 border-slate-700/60" }
};

export const RESPONSE_ACTION_STATUS = {
  proposed: { label: "Proposed", bg: "bg-yellow-950/40 text-yellow-400 border-yellow-800/60" },
  approved: { label: "Approved (Simulated)", bg: "bg-green-950/40 text-green-400 border-green-800/60" },
  simulated: { label: "Simulated", bg: "bg-cyan-950/40 text-cyan-400 border-cyan-800/60" },
  rejected: { label: "Rejected", bg: "bg-red-950/40 text-red-400 border-red-800/60" }
};

export const ASSET_CRITICALITY = {
  critical: { label: "Critical", text: "text-red-400" },
  high: { label: "High", text: "text-orange-400" },
  medium: { label: "Medium", text: "text-yellow-400" },
  low: { label: "Low", text: "text-green-400" }
};

export const VULN_STATUS = {
  open: { label: "Open", bg: "bg-red-950/40 text-red-400 border-red-800/60" },
  patched: { label: "Patched", bg: "bg-green-950/40 text-green-400 border-green-800/60" },
  mitigated: { label: "Mitigated", bg: "bg-yellow-950/40 text-yellow-400 border-yellow-800/60" },
  accepted: { label: "Risk Accepted", bg: "bg-slate-900 text-slate-400 border-slate-700/60" }
};

export const CNI_TOPOLOGY_LEGEND = {
  internet: { label: "External Internet Z", color: "#38bdf8" },
  dmz: { label: "Demilitarized Zone (DMZ)", color: "#fb7185" },
  internal: { label: "Corporate LAN / IT", color: "#818cf8" },
  scada: { label: "SCADA / ICS OT Net", color: "#a78bfa" },
  management: { label: "Management Network", color: "#34d399" }
};
