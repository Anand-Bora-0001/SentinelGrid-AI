import React, { useState, useEffect, useRef, useMemo } from "react";
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
  Line,
} from "react-simple-maps";
import {
  Globe,
  Activity,
  Filter,
  AlertTriangle,
  Server,
  Eye,
} from "lucide-react";
import DashboardLayout from "../components/layout/DashboardLayout";
import LoadingState from "../components/common/LoadingState";
import SeverityBadge from "../components/common/SeverityBadge";
import { api } from "../api/client";

// ── Natural Earth TopoJSON (110m — lightweight) ──────────────────────────────
const GEO_URL =
  "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// ── CNI Target: New Delhi ────────────────────────────────────────────────────
const TARGET = [77.23, 28.61]; // [lng, lat]

// ── Demo fallback threat data ────────────────────────────────────────────────
const DEMO_THREATS = [
  { id: 1,  source_ip: "95.163.220.12",  severity: "CRITICAL", action: "SSH Brute Force",        protocol: "SSH",   location: { lat: 55.7558, lng: 37.6173, country: "Russia",         country_code: "RU", city: "Moscow"    } },
  { id: 2,  source_ip: "220.181.38.148", severity: "CRITICAL", action: "SQL Injection Attempt",   protocol: "HTTP",  location: { lat: 39.9042, lng: 116.407, country: "China",          country_code: "CN", city: "Beijing"   } },
  { id: 3,  source_ip: "198.51.100.42",  severity: "HIGH",     action: "Port Scan Detected",      protocol: "TCP",   location: { lat: 37.0902, lng: -95.71, country: "United States",   country_code: "US", city: "Kansas"    } },
  { id: 4,  source_ip: "46.165.2.14",    severity: "HIGH",     action: "C2 Beacon",               protocol: "HTTPS", location: { lat: 52.52,   lng: 13.405, country: "Germany",         country_code: "DE", city: "Berlin"    } },
  { id: 5,  source_ip: "200.221.2.45",   severity: "MEDIUM",   action: "DDoS Amplification",      protocol: "UDP",   location: { lat: -23.55,  lng: -46.63, country: "Brazil",          country_code: "BR", city: "São Paulo" } },
  { id: 6,  source_ip: "82.197.200.4",   severity: "HIGH",     action: "Exploit Kit Download",    protocol: "HTTP",  location: { lat: 52.3676, lng: 4.9041, country: "Netherlands",     country_code: "NL", city: "Amsterdam" } },
  { id: 7,  source_ip: "101.100.180.2",  severity: "MEDIUM",   action: "Auth Spray Attack",       protocol: "SSH",   location: { lat: 1.3521,  lng: 103.82, country: "Singapore",       country_code: "SG", city: "Singapore" } },
  { id: 8,  source_ip: "210.140.10.10",  severity: "CRITICAL", action: "Zero-Day Exploit",        protocol: "TCP",   location: { lat: 35.6762, lng: 139.65, country: "Japan",           country_code: "JP", city: "Tokyo"     } },
  { id: 9,  source_ip: "109.228.0.1",    severity: "LOW",      action: "Recon Scan",              protocol: "ICMP",  location: { lat: 51.5074, lng: -0.128, country: "United Kingdom",  country_code: "GB", city: "London"    } },
  { id: 10, source_ip: "41.203.64.1",    severity: "MEDIUM",   action: "Phishing Infrastructure", protocol: "HTTP",  location: { lat: 9.0579,  lng: 7.4951, country: "Nigeria",         country_code: "NG", city: "Abuja"     } },
  { id: 11, source_ip: "185.220.101.5",  severity: "HIGH",     action: "Tor Exit Node Attack",    protocol: "HTTPS", location: { lat: 50.0755, lng: 14.438, country: "Czech Republic",  country_code: "CZ", city: "Prague"    } },
  { id: 12, source_ip: "198.41.0.4",     severity: "LOW",      action: "DNS Enumeration",         protocol: "DNS",   location: { lat: 43.6532, lng: -79.38, country: "Canada",          country_code: "CA", city: "Toronto"   } },
];

// ── Severity helpers ─────────────────────────────────────────────────────────
const severityColor = (sev) => {
  switch (sev) {
    case "CRITICAL": return "#ef4444";
    case "HIGH":     return "#f97316";
    case "MEDIUM":   return "#eab308";
    default:         return "#22c55e";
  }
};

// ── Pulsing marker component ─────────────────────────────────────────────────
function PulseMarker({ coordinates, color, size = 6, onClick }) {
  return (
    <Marker coordinates={coordinates}>
      <g onClick={onClick} style={{ cursor: "pointer" }}>
        {/* Outer pulse ring */}
        <circle r={size * 2.5} fill={color} opacity="0.15">
          <animate attributeName="r" values={`${size * 1.5};${size * 3};${size * 1.5}`} dur="2s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.2;0.04;0.2" dur="2s" repeatCount="indefinite" />
        </circle>
        {/* Mid ring */}
        <circle r={size * 1.2} fill={color} opacity="0.35">
          <animate attributeName="r" values={`${size};${size * 1.8};${size}`} dur="1.8s" repeatCount="indefinite" />
        </circle>
        {/* Core dot */}
        <circle r={size} fill={color} stroke={color} strokeWidth="0.5" opacity="0.9" />
        {/* White center */}
        <circle r={size * 0.35} fill="#fff" opacity="0.9" />
      </g>
    </Marker>
  );
}

export default function ThreatMap() {
  const [loading, setLoading] = useState(true);
  const [allEvents, setAllEvents] = useState([]);
  const [filteredEvents, setFilteredEvents] = useState([]);
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState(null);

  // ── Load data ──────────────────────────────────────────────────────────────
  const loadData = async () => {
    try {
      const data = await api.get("/api/telemetry", { limit: 100 });
      const items = data?.items || [];
      const geoItems = items.filter((e) => e.location?.lat && e.location?.lng);
      setAllEvents(geoItems);
    } catch (err) {
      setAllEvents([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, []);

  // ── Apply filters ─────────────────────────────────────────────────────────
  useEffect(() => {
    let events = [...allEvents];
    if (filterSeverity !== "all")
      events = events.filter((e) => e.severity === filterSeverity);
    if (filterType !== "all")
      events = events.filter(
        (e) => (e.event_type || e.protocol) === filterType
      );
    setFilteredEvents(events);
  }, [allEvents, filterSeverity, filterType]);

  // ── Attack sources with coordinates ────────────────────────────────────────
  const attackSources = useMemo(
    () =>
      filteredEvents
        .filter((e) => e.location?.lat && e.location?.lng)
        .slice(0, 20),
    [filteredEvents]
  );

  // ── Counters ──────────────────────────────────────────────────────────────
  const countBySeverity = (s) =>
    filteredEvents.filter((e) => e.severity === s).length;

  if (loading) {
    return (
      <DashboardLayout title="Geopolitical Threat Origin Map">
        <LoadingState message="Connecting to global security sensor network..." />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Geopolitical Threat Origin Map">
      <div className="flex flex-col gap-4 h-[calc(100vh-130px)]">
        {/* ── Stat Bar ──────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 shrink-0">
          {[
            { label: "CRITICAL", count: countBySeverity("CRITICAL"), color: "text-red-400",    bg: "bg-red-950/40 border-red-500/30" },
            { label: "HIGH",     count: countBySeverity("HIGH"),     color: "text-orange-400", bg: "bg-orange-950/40 border-orange-500/30" },
            { label: "MEDIUM",   count: countBySeverity("MEDIUM"),   color: "text-yellow-400", bg: "bg-yellow-950/40 border-yellow-500/30" },
            { label: "LOW",      count: countBySeverity("LOW"),      color: "text-green-400",  bg: "bg-green-950/40 border-green-500/30" },
          ].map((s) => (
            <div key={s.label} className={`flex items-center gap-3 px-4 py-2 rounded-lg border ${s.bg} flex-1`}>
              <AlertTriangle className={`h-4 w-4 ${s.color} shrink-0`} />
              <div>
                <div className={`text-lg font-bold font-mono ${s.color}`}>{s.count}</div>
                <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">{s.label}</div>
              </div>
            </div>
          ))}
          <div className="flex items-center gap-3 px-4 py-2 rounded-lg border bg-cyan-950/40 border-cyan-500/30 flex-1">
            <Eye className="h-4 w-4 text-cyber-cyan shrink-0" />
            <div>
              <div className="text-lg font-bold font-mono text-cyber-cyan">{filteredEvents.length}</div>
              <div className="text-[9px] text-slate-500 font-mono uppercase tracking-wider">External Threats</div>
            </div>
          </div>
        </div>

        {/* ── Main Grid ─────────────────────────────────────────────── */}
        <div className="flex-1 grid grid-cols-1 xl:grid-cols-4 gap-4 min-h-0">
          {/* Map Panel */}
          <div className="xl:col-span-3 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-4 flex flex-col gap-3 overflow-hidden">
            {/* Header + filters */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3 shrink-0">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyber-cyan" />
                Geopolitical Threat Visualization
              </h3>
              <div className="flex items-center gap-2">
                <Filter className="h-3.5 w-3.5 text-slate-500" />
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded px-2 py-1 focus:outline-none focus:border-cyber-cyan font-mono"
                >
                  <option value="all">ALL SEVERITIES</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded px-2 py-1 focus:outline-none focus:border-cyber-cyan font-mono"
                >
                  <option value="all">ALL TYPES</option>
                  <option value="SSH">SSH</option>
                  <option value="HTTP">HTTP</option>
                  <option value="HTTPS">HTTPS</option>
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="ICMP">ICMP</option>
                  <option value="DNS">DNS</option>
                </select>
              </div>
            </div>

            {/* Map canvas */}
            <div className="flex-1 flex items-center justify-center overflow-hidden rounded-lg bg-[#020a18] relative">
              {/* Faint radial glow behind map */}
              <div
                className="absolute inset-0 pointer-events-none"
                style={{
                  background:
                    "radial-gradient(ellipse at 60% 40%, rgba(6,182,212,0.06) 0%, transparent 60%)",
                }}
              />

              <ComposableMap
                projection="geoMercator"
                projectionConfig={{
                  scale: 130,
                  center: [40, 25],
                }}
                style={{ width: "100%", height: "100%" }}
              >
                {/* Country shapes */}
                <Geographies geography={GEO_URL}>
                  {({ geographies }) =>
                    geographies.map((geo) => (
                      <Geography
                        key={geo.rsmKey}
                        geography={geo}
                        fill="#112240"
                        stroke="#1e3a5f"
                        strokeWidth={0.4}
                        style={{
                          default: { outline: "none" },
                          hover:   { fill: "#1a365d", outline: "none" },
                          pressed: { outline: "none" },
                        }}
                      />
                    ))
                  }
                </Geographies>

                {/* Attack arc lines to target */}
                {attackSources.map((event, idx) => {
                  const from = [event.location.lng, event.location.lat];
                  const color = severityColor(event.severity);
                  return (
                    <Line
                      key={`line-${event.id}-${idx}`}
                      from={from}
                      to={TARGET}
                      stroke={color}
                      strokeWidth={1.5}
                      strokeLinecap="round"
                      strokeDasharray="6 4"
                      strokeOpacity={0.55}
                      style={{
                        filter: `drop-shadow(0 0 4px ${color})`,
                      }}
                    />
                  );
                })}

                {/* Attack source markers */}
                {attackSources.map((event, idx) => (
                  <PulseMarker
                    key={`marker-${event.id}-${idx}`}
                    coordinates={[event.location.lng, event.location.lat]}
                    color={severityColor(event.severity)}
                    size={event.severity === "CRITICAL" ? 6 : event.severity === "HIGH" ? 5 : 4}
                    onClick={() => setSelectedEvent(event)}
                  />
                ))}

                {/* Target marker — CNI Hub */}
                <PulseMarker
                  coordinates={TARGET}
                  color="#06b6d4"
                  size={8}
                />
                <Marker coordinates={TARGET}>
                  <text
                    textAnchor="start"
                    x={14}
                    y={-8}
                    style={{
                      fill: "#06b6d4",
                      fontSize: "9px",
                      fontFamily: "monospace",
                      fontWeight: "bold",
                      letterSpacing: "0.1em",
                    }}
                  >
                    CNI HUB
                  </text>
                  <text
                    textAnchor="start"
                    x={14}
                    y={2}
                    style={{
                      fill: "#64748b",
                      fontSize: "7px",
                      fontFamily: "monospace",
                    }}
                  >
                    New Delhi, IN
                  </text>
                </Marker>
              </ComposableMap>
            </div>

            {/* Map footer */}
            <div className="shrink-0 flex items-center gap-3 bg-slate-900/60 border border-slate-800 rounded-lg p-2.5 text-xs">
              <Server className="h-4 w-4 text-cyber-cyan shrink-0" />
              <span className="text-slate-400 font-mono">
                Target:{" "}
                <strong className="text-white">
                  SentinelGrid CNI Gateway Hub
                </strong>{" "}
                (28.61°N 77.23°E) — Tracking{" "}
                <strong className="text-cyber-cyan">
                  {attackSources.length}
                </strong>{" "}
                active threat vectors from{" "}
                <strong className="text-orange-400">
                  {new Set(attackSources.map((p) => p.location?.country_code)).size}
                </strong>{" "}
                nations
              </span>
            </div>
          </div>

          {/* ── Live Feed Sidebar ──────────────────────────────────── */}
          <div className="xl:col-span-1 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md p-4 flex flex-col gap-3 overflow-hidden">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2 border-b border-slate-800 pb-3 shrink-0">
              <Activity className="h-4 w-4 text-cyber-purple animate-pulse" />
              Real-Time Stream Feed
            </h3>

            <div className="flex-1 space-y-2 overflow-y-auto pr-1">
              {filteredEvents.length === 0 ? (
                <div className="text-center py-10 text-xs text-slate-500 font-mono">
                  No alerts matching active filters.
                </div>
              ) : (
                filteredEvents.slice(0, 30).map((event) => {
                  const color = severityColor(event.severity);
                  return (
                    <div
                      key={event.id}
                      onClick={() => setSelectedEvent(event)}
                      className={`p-2.5 rounded-lg border text-left cursor-pointer transition-all duration-150 ${
                        selectedEvent?.id === event.id
                          ? "bg-slate-800/70 border-cyber-cyan"
                          : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] text-cyber-cyan font-mono font-bold">
                          {event.protocol || event.event_type || "TCP"}
                        </span>
                        <SeverityBadge severity={event.severity} />
                      </div>
                      <p className="text-[11px] font-bold text-white leading-tight truncate">
                        {event.action || event.event_type || "Suspicious Activity"}
                      </p>
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono mt-1">
                        <span className="truncate max-w-[100px]">
                          {event.source_ip || "unknown"}
                        </span>
                        <span>{event.location?.country_code || "??"}</span>
                      </div>
                      {/* Severity bar */}
                      <div className="mt-1.5 w-full bg-slate-800 rounded-full h-0.5">
                        <div
                          className="h-0.5 rounded-full transition-all"
                          style={{
                            width:
                              event.severity === "CRITICAL"
                                ? "100%"
                                : event.severity === "HIGH"
                                ? "75%"
                                : event.severity === "MEDIUM"
                                ? "50%"
                                : "25%",
                            backgroundColor: color,
                          }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Selected event detail */}
            {selectedEvent && (
              <div className="shrink-0 pt-3 border-t border-slate-800 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <div className="flex justify-between items-start mb-2">
                  <span className="text-[9px] font-mono text-cyber-cyan font-semibold uppercase tracking-wider">
                    {selectedEvent.location?.country || "Unknown"} —{" "}
                    {selectedEvent.location?.city || ""}
                  </span>
                  <button
                    onClick={() => setSelectedEvent(null)}
                    className="text-[10px] text-slate-500 hover:text-white"
                  >
                    
                  </button>
                </div>
                <p className="text-xs font-bold text-white mb-2 leading-tight">
                  {selectedEvent.action || "Threat Event"}
                </p>
                <div className="text-[10px] space-y-1 font-mono text-slate-400">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Source IP:</span>
                    <span className="text-red-400">
                      {selectedEvent.source_ip}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Protocol:</span>
                    <span>{selectedEvent.protocol || "TCP"}</span>
                  </div>
                  {selectedEvent.location && (
                    <div className="flex justify-between">
                      <span className="text-slate-500">Location:</span>
                      <span>
                        {selectedEvent.location.city},{" "}
                        {selectedEvent.location.country_code}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-slate-500">Severity:</span>
                    <span
                      style={{ color: severityColor(selectedEvent.severity) }}
                      className="font-bold"
                    >
                      {selectedEvent.severity}
                    </span>
                  </div>
                  {selectedEvent.is_anomaly && (
                    <div className="mt-2 text-[10px] text-cyber-purple font-semibold">
                      ️ AI Anomaly — {Math.round(selectedEvent.risk_score || 85)}%
                      Risk
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
