import React from "react";

export default function RiskGauge({ score, size = 160 }) {
  const parsedScore = Math.min(Math.max(Number(score || 0), 0), 100);
  const radius = size * 0.4;
  const strokeWidth = size * 0.08;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (parsedScore / 100) * circumference;

  let scoreColor = "stroke-cyber-success drop-shadow-[0_0_8px_rgba(34,197,94,0.4)]";
  let textColor = "text-cyber-success";
  let textLabel = "Resilient";

  if (parsedScore >= 75) {
    scoreColor = "stroke-cyber-danger drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]";
    textColor = "text-cyber-danger";
    textLabel = "Critical Risk";
  } else if (parsedScore >= 50) {
    scoreColor = "stroke-cyber-orange drop-shadow-[0_0_8px_rgba(249,115,22,0.4)]";
    textColor = "text-cyber-orange";
    textLabel = "Elevated Risk";
  } else if (parsedScore >= 25) {
    scoreColor = "stroke-cyber-warning drop-shadow-[0_0_8px_rgba(234,179,8,0.4)]";
    textColor = "text-cyber-warning";
    textLabel = "Medium Risk";
  }

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full transform -rotate-90">
          {/* Background track circle */}
          <circle
            className="stroke-slate-800"
            fill="transparent"
            strokeWidth={strokeWidth}
            r={radius}
            cx={size / 2}
            cy={size / 2}
          />
          {/* Active progress circle */}
          <circle
            className={`transition-all duration-1000 ease-out ${scoreColor}`}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            r={radius}
            cx={size / 2}
            cy={size / 2}
          />
        </svg>
        
        {/* Core details inside the gauge */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-sm font-semibold uppercase tracking-wider text-slate-500 font-mono">
            Risk Score
          </span>
          <span className={`text-4xl font-extrabold tracking-tighter my-0.5 ${textColor}`}>
            {parsedScore}
          </span>
          <span className={`text-xs font-bold font-mono tracking-wide ${textColor}`}>
            {textLabel}
          </span>
        </div>
      </div>
    </div>
  );
}
