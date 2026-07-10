import React from "react";
import { SEVERITY_LEVELS } from "../../utils/constants";

export default function SeverityBadge({ severity }) {
  const normSeverity = String(severity).toUpperCase();
  const config = SEVERITY_LEVELS[normSeverity] || SEVERITY_LEVELS.INFO;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider border font-mono ${config.bg}`}>
      {config.label}
    </span>
  );
}
