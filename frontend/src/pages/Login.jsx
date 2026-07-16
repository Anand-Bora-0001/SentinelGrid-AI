import React, { useState } from "react";
import { Terminal, Shield, Lock, User, AlertCircle, RefreshCw } from "lucide-react";
import { api } from "../api/client";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setError("Provide both username and security key.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      await api.login(username, password);
      // Success redirect to dashboard
      window.location.href = "/";
    } catch (err) {
      setError(err.message || "Invalid operator credentials.");
    } finally {
      setLoading(false);
    }
  };

  const fillCredentials = (user, pass) => {
    setUsername(user);
    setPassword(pass);
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center bg-cyber-bg relative overflow-hidden font-sans scanline-effect">
      {/* Decorative neon nodes */}
      <div className="absolute top-1/4 left-1/4 h-72 w-72 rounded-full bg-cyber-cyan/5 filter blur-[80px]" />
      <div className="absolute bottom-1/4 right-1/4 h-72 w-72 rounded-full bg-cyber-purple/5 filter blur-[80px]" />

      {/* Login Card */}
      <div className="w-full max-w-md p-8 rounded-2xl glass-panel border border-slate-800 shadow-2xl relative z-10 mx-4">
        {/* Platform Title */}
        <div className="text-center mb-8">
          <div className="inline-flex p-3.5 rounded-xl bg-slate-900 border border-slate-800/80 text-cyber-cyan mb-4 shadow-md">
            <Shield className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white m-0 uppercase">
            SENTINEL<span className="text-cyber-cyan">GRID</span>
          </h1>
          <p className="text-slate-400 text-xs mt-1.5 font-mono uppercase tracking-wider">
            AI Cyber Resilience Gateway
          </p>
        </div>

        {/* Error notification */}
        {error && (
          <div className="mb-6 p-4 rounded-lg bg-red-950/40 border border-red-500/20 text-red-400 text-xs flex items-start gap-2.5">
            <AlertCircle className="h-4.5 w-4.5 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Username */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
              Operator Identifier
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <User className="h-4 w-4" />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. admin"
                className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan text-white placeholder-slate-600 text-sm transition-all focus:outline-none"
                disabled={loading}
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 font-mono">
              Access Encryption Key
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-slate-500">
                <Lock className="h-4 w-4" />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-10 pr-4 py-3 rounded-lg bg-slate-950 border border-slate-800 focus:border-cyber-cyan focus:ring-1 focus:ring-cyber-cyan text-white placeholder-slate-600 text-sm transition-all focus:outline-none"
                disabled={loading}
              />
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 px-4 rounded-lg bg-cyber-cyan text-cyber-bg font-semibold text-sm hover:bg-cyber-cyan/95 focus:outline-none transition-all flex items-center justify-center gap-2 shadow-md active:scale-98 font-mono disabled:opacity-50"
          >
            {loading ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Terminal className="h-4 w-4" />
            )}
            <span>{loading ? "INITIALIZING SECURE SESSION..." : "ESTABLISH SECURITY CONNECTION"}</span>
          </button>
        </form>

        {/* Demo autocomplete helpers */}
        <div className="mt-8 pt-6 border-t border-slate-850">
          <p className="text-[10px] font-mono text-slate-500 uppercase tracking-wider text-center mb-3">
            Demo Credentials (CNI Access)
          </p>
          <div className="grid grid-cols-2 gap-3">
            <button
              onClick={() => fillCredentials("admin", "admin123")}
              className="py-2 px-3 rounded bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 hover:text-cyber-cyan hover:border-cyber-cyan/30 transition-all font-mono"
            >
              Role: CISO / Admin
            </button>
            <button
              onClick={() => fillCredentials("analyst", "analyst123")}
              className="py-2 px-3 rounded bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 hover:text-cyber-purple hover:border-cyber-purple/30 transition-all font-mono"
            >
              Role: SOC Analyst
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
