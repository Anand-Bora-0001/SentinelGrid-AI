import React, { useState } from 'react';
import { api } from '../api/client';
import { 
  ShieldAlert, 
  Search, 
  MessageSquare, 
  BookOpen, 
  AlertTriangle,
  Send,
  Loader
} from 'lucide-react';
import DashboardLayout from "../components/layout/DashboardLayout";

const ThreatIntelligenceCenter = () => {
  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState(null);
  const [error, setError] = useState('');

  const askThreatIntel = async (e) => {
    e.preventDefault();
    if (!question.trim()) return;

    setLoading(true);
    setError('');
    setResponse(null);

    try {
      const res = await api.post('/threat-intel/ask', { question });
      setResponse(res.data);
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to fetch threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout title="Threat Intelligence Center">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-indigo-400" />
            Threat Intelligence Center
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Ask AI, analyze CVEs, and map ATT&CK techniques with SentinelGrid Engine.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Chat/Ask AI */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden flex flex-col h-[600px]">
            <div className="p-4 border-b border-slate-700 bg-slate-800/50 flex items-center gap-2">
              <MessageSquare className="h-5 w-5 text-blue-400" />
              <h2 className="font-semibold text-white">Ask SentinelGrid AI</h2>
            </div>
            
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* Welcome message */}
              {!response && !loading && (
                <div className="flex items-start gap-3 text-slate-300 bg-slate-700/30 p-4 rounded-lg">
                  <ShieldAlert className="h-6 w-6 text-indigo-400 mt-1" />
                  <div>
                    <p className="font-medium text-white mb-1">Welcome to Threat Intelligence</p>
                    <p className="text-sm">You can ask me about threat predictions, MITRE ATT&CK techniques, vulnerabilities, and recommended defenses.</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button 
                        onClick={() => setQuestion("Why was T1003 predicted?")}
                        className="text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-full transition-colors"
                      >
                        "Why was T1003 predicted?"
                      </button>
                      <button 
                        onClick={() => setQuestion("What is Log4Shell?")}
                        className="text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-full transition-colors"
                      >
                        "What is Log4Shell?"
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Error state */}
              {error && (
                <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-lg flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 shrink-0" />
                  <p className="text-sm">{error}</p>
                </div>
              )}

              {/* User question */}
              {response && (
                <div className="flex justify-end">
                  <div className="bg-indigo-600 text-white p-3 rounded-l-xl rounded-tr-xl max-w-[80%]">
                    <p className="text-sm">{response.question}</p>
                  </div>
                </div>
              )}

              {/* AI Response */}
              {loading && (
                <div className="flex items-center gap-2 text-slate-400 p-3">
                  <Loader className="h-5 w-5 animate-spin" />
                  <span className="text-sm">Analyzing threat data...</span>
                </div>
              )}

              {response && (
                <div className="flex items-start gap-3 max-w-[90%]">
                  <div className="bg-slate-700 rounded-full p-2 shrink-0">
                    <ShieldAlert className="h-5 w-5 text-indigo-400" />
                  </div>
                  <div className="bg-slate-700/50 p-4 rounded-r-xl rounded-bl-xl border border-slate-600 space-y-4 w-full">
                    <div>
                      <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Explanation</h4>
                      <p className="text-sm text-slate-200 leading-relaxed">{response.answer}</p>
                    </div>
                    
                    {response.sources && response.sources.length > 0 && (
                      <div className="pt-3 border-t border-slate-600">
                        <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Sources</h4>
                        <div className="flex flex-wrap gap-2">
                          {response.sources.map((source, idx) => (
                            <span key={idx} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                              <BookOpen className="h-3 w-3" />
                              {source}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 bg-slate-800 border-t border-slate-700">
              <form onSubmit={askThreatIntel} className="relative">
                <input
                  type="text"
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask about a CVE, ATT&CK technique, or threat..."
                  className="w-full bg-slate-900 border border-slate-600 rounded-lg pl-4 pr-12 py-3 text-sm text-white placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                  disabled={loading}
                />
                <button
                  type="submit"
                  disabled={!question.trim() || loading}
                  className="absolute right-2 top-1/2 -translate-y-1/2 p-2 text-slate-400 hover:text-indigo-400 disabled:opacity-50 disabled:hover:text-slate-400 transition-colors"
                >
                  <Send className="h-4 w-4" />
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Right Column - Quick Lookups */}
        <div className="space-y-6">
          <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
            <div className="p-4 border-b border-slate-700 bg-slate-800/50 flex items-center gap-2">
              <Search className="h-5 w-5 text-emerald-400" />
              <h2 className="font-semibold text-white">Quick Lookups</h2>
            </div>
            <div className="p-4 space-y-4">
              <button 
                onClick={() => setQuestion("What does ATT&CK T1003 mean?")}
                className="w-full text-left p-3 rounded-lg border border-slate-600 bg-slate-700/30 hover:bg-slate-700 transition-colors group"
              >
                <div className="font-medium text-emerald-400 text-sm group-hover:text-emerald-300">ATT&CK Lookup</div>
                <div className="text-xs text-slate-400 mt-1">Search MITRE techniques and mitigations</div>
              </button>
              
              <button 
                onClick={() => setQuestion("Explain CVE-2021-44228")}
                className="w-full text-left p-3 rounded-lg border border-slate-600 bg-slate-700/30 hover:bg-slate-700 transition-colors group"
              >
                <div className="font-medium text-orange-400 text-sm group-hover:text-orange-300">CVE Lookup</div>
                <div className="text-xs text-slate-400 mt-1">Query vulnerability details and impact</div>
              </button>
              
              <button 
                onClick={() => setQuestion("How should defenders respond to Ransomware?")}
                className="w-full text-left p-3 rounded-lg border border-slate-600 bg-slate-700/30 hover:bg-slate-700 transition-colors group"
              >
                <div className="font-medium text-blue-400 text-sm group-hover:text-blue-300">Recommended Defenses</div>
                <div className="text-xs text-slate-400 mt-1">Get actionable mitigation strategies</div>
              </button>
            </div>
          </div>
        </div>
      </div>
      </div>
    </DashboardLayout>
  );
};

export default ThreatIntelligenceCenter;
