import React, { useState, useEffect } from 'react';
import DashboardLayout from '../components/layout/DashboardLayout';

const UEBADashboard = () => {
  const [highRiskEntities, setHighRiskEntities] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);

  // Mock data for the UI since the API might not have data yet
  const mockHighRiskEntities = [
    { entity_id: 'admin_user', entity_type: 'user', risk_score: 94, explanations: ['login occurred at 02:14 AM', 'first login from foreign location'] },
    { entity_id: '192.168.1.105', entity_type: 'device', risk_score: 82, explanations: ['12x normal file access volume'] },
    { entity_id: 'service_account', entity_type: 'user', risk_score: 75, explanations: ['abnormal network traffic pattern'] }
  ];

  const mockAnomalies = [
    { id: 1, timestamp: new Date().toISOString(), event_type: 'behavior_anomaly', deviation_score: 0.85, details: { file_access: 120 } },
    { id: 2, timestamp: new Date(Date.now() - 3600000).toISOString(), event_type: 'location_anomaly', deviation_score: 0.92, details: { location: 'RU' } },
  ];

  useEffect(() => {
    // In a real implementation, this would fetch from the actual API endpoints
    // For now, we simulate a network delay and use mock data
    const timer = setTimeout(() => {
      setHighRiskEntities(mockHighRiskEntities);
      setAnomalies(mockAnomalies);
      setLoading(false);
    }, 1000);
    return () => clearTimeout(timer);
  }, []);

  if (loading) {
    return <div className="p-8 text-center text-gray-400">Loading UEBA analytics...</div>;
  }

  // Split high risk entities
  const highRiskUsers = highRiskEntities.filter(e => e.entity_type === 'user');
  const highRiskDevices = highRiskEntities.filter(e => e.entity_type === 'device');

  // Overall Risk Score (max risk of all entities)
  const maxRisk = highRiskEntities.length > 0 ? Math.max(...highRiskEntities.map(e => e.risk_score)) : 0;

  return (
    <DashboardLayout title="Behavioral Anomaly Detection (UEBA)">
      <div className="p-6 space-y-6 bg-gray-900 min-h-screen text-gray-100">
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">
          Behavioral Anomaly Detection (UEBA)
        </h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* Widget 1: Risk Score Gauge */}
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg flex flex-col items-center justify-center">
          <h2 className="text-lg font-semibold text-gray-300 mb-4">Maximum Org Risk Score</h2>
          <div className="relative w-48 h-48">
            <svg className="w-full h-full" viewBox="0 0 100 100">
              <circle className="text-gray-700 stroke-current" strokeWidth="10" cx="50" cy="50" r="40" fill="transparent"></circle>
              <circle className={`${maxRisk > 80 ? 'text-red-500' : maxRisk > 50 ? 'text-yellow-500' : 'text-green-500'} stroke-current`} 
                strokeWidth="10" strokeLinecap="round" cx="50" cy="50" r="40" fill="transparent" 
                strokeDasharray={`${maxRisk * 2.51} 251.2`} transform="rotate(-90 50 50)"></circle>
            </svg>
            <div className="absolute inset-0 flex items-center justify-center flex-col">
              <span className="text-4xl font-bold">{Math.round(maxRisk)}</span>
              <span className="text-xs text-gray-400">/ 100</span>
            </div>
          </div>
        </div>

        {/* Widget 3: High Risk Users */}
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg col-span-1 md:col-span-2 hover:border-red-500/30 transition-colors">
          <h2 className="text-lg font-semibold text-red-400 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>
            High Risk Users
          </h2>
          <div className="space-y-4">
            {highRiskUsers.map((user, idx) => (
              <div key={idx} className="bg-gray-900 p-4 rounded-lg border border-red-900/50 flex justify-between items-start">
                <div>
                  <div className="font-bold text-gray-200">{user.entity_id}</div>
                  <ul className="list-disc list-inside text-sm text-gray-400 mt-2">
                    {user.explanations.map((exp, i) => <li key={i}>{exp}</li>)}
                  </ul>
                </div>
                <div className="bg-red-500/20 text-red-400 px-3 py-1 rounded-full font-bold">
                  {user.risk_score}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* Widget 4: High Risk Devices */}
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg hover:border-orange-500/30 transition-colors">
          <h2 className="text-lg font-semibold text-orange-400 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
            High Risk Devices
          </h2>
          <div className="space-y-4">
            {highRiskDevices.map((device, idx) => (
              <div key={idx} className="bg-gray-900 p-4 rounded-lg border border-orange-900/50 flex justify-between items-center">
                <div>
                  <div className="font-bold text-gray-200">{device.entity_id}</div>
                  <div className="text-xs text-gray-400 mt-1">{device.explanations[0]}</div>
                </div>
                <div className="bg-orange-500/20 text-orange-400 px-3 py-1 rounded-full font-bold">
                  {device.risk_score}
                </div>
              </div>
            ))}
            {highRiskDevices.length === 0 && <div className="text-gray-500 text-sm">No high risk devices detected.</div>}
          </div>
        </div>

        {/* Widget 2: Top Anomalies */}
        <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
          <h2 className="text-lg font-semibold text-gray-300 mb-4 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            Top Anomalies
          </h2>
          <div className="space-y-3">
            {anomalies.map(anomaly => (
              <div key={anomaly.id} className="bg-gray-900 p-3 rounded-lg border border-gray-700 flex flex-col">
                <div className="flex justify-between">
                  <span className="text-sm font-semibold text-purple-400">{anomaly.event_type.replace('_', ' ').toUpperCase()}</span>
                  <span className="text-xs text-gray-500">{new Date(anomaly.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="text-sm text-gray-400 mt-2 font-mono bg-black p-2 rounded">
                  {JSON.stringify(anomaly.details)}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Widget 5: Behavioral Timeline */}
      <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
        <h2 className="text-lg font-semibold text-gray-300 mb-4 flex items-center">
          <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          Behavioral Timeline
        </h2>
        <div className="relative border-l border-gray-700 ml-3 space-y-6">
          {anomalies.map((anomaly, idx) => (
            <div key={idx} className="pl-6 relative">
              <div className="absolute w-3 h-3 bg-blue-500 rounded-full -left-[6.5px] top-1.5 shadow-[0_0_10px_rgba(59,130,246,0.8)]"></div>
              <p className="text-sm text-gray-400">{new Date(anomaly.timestamp).toLocaleString()}</p>
              <h4 className="text-md font-semibold text-gray-200 mt-1">{anomaly.event_type.replace('_', ' ')} detected</h4>
              <p className="text-sm text-gray-500 mt-1">Anomaly score: {anomaly.deviation_score.toFixed(2)}</p>
            </div>
          ))}
        </div>
      </div>

    </div>
    </DashboardLayout>
  );
};

export default UEBADashboard;
