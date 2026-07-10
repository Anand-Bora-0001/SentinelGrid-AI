import React from "react";
import { RefreshCw } from "lucide-react";

export default function LoadingState({ message = "Decrypting security feeds..." }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-400">
      <div className="relative flex items-center justify-center">
        <div className="absolute h-12 w-12 rounded-full border border-cyber-cyan/15 animate-ping" />
        <div className="h-10 w-10 rounded-full border-2 border-t-cyber-cyan border-r-transparent border-b-transparent border-l-transparent animate-spin flex items-center justify-center">
          <RefreshCw className="h-4 w-4 text-cyber-cyan" />
        </div>
      </div>
      <p className="mt-4 text-xs font-mono font-medium tracking-widest uppercase text-slate-500 animate-pulse">
        {message}
      </p>
    </div>
  );
}
