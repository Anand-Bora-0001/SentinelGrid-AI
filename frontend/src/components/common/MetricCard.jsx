import React from "react";
import { ArrowUpRight, ArrowDownRight } from "lucide-react";

export default function MetricCard({ 
  title, 
  value, 
  icon: Icon, 
  subtext, 
  trendValue, 
  trendDirection, 
  glowColor = "cyan" 
}) {
  const shadowClasses = {
    cyan: "hover:shadow-cyber-neon hover:border-cyber-cyan/30",
    purple: "hover:shadow-cyber-neon-purple hover:border-cyber-purple/30",
    danger: "hover:shadow-cyber-neon-danger hover:border-cyber-danger/30"
  }[glowColor] || "hover:shadow-cyber-neon hover:border-cyber-cyan/30";

  return (
    <div className={`p-6 rounded-xl bg-cyber-card/65 border border-slate-800/80 backdrop-blur-md transition-all duration-300 ${shadowClasses}`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
            {title}
          </p>
          <h3 className="text-3xl font-bold mt-2 text-white font-sans tracking-tight">
            {value}
          </h3>
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg bg-slate-900 border border-slate-850 flex items-center justify-center ${
            glowColor === "cyan" ? "text-cyber-cyan" : 
            glowColor === "purple" ? "text-cyber-purple" : "text-cyber-danger"
          }`}>
            <Icon className="h-5 w-5" />
          </div>
        )}
      </div>
      
      {/* Subtext and Trends */}
      {(subtext || trendValue) && (
        <div className="flex items-center gap-2 mt-4 text-xs">
          {trendValue && (
            <span className={`flex items-center font-mono font-medium ${
              trendDirection === "up" ? "text-cyber-danger" : "text-cyber-success"
            }`}>
              {trendDirection === "up" ? (
                <ArrowUpRight className="h-3.5 w-3.5 mr-0.5" />
              ) : (
                <ArrowDownRight className="h-3.5 w-3.5 mr-0.5" />
              )}
              {trendValue}
            </span>
          )}
          {subtext && <span className="text-slate-500 font-medium">{subtext}</span>}
        </div>
      )}
    </div>
  );
}
