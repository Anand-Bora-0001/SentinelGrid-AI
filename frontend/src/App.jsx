import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { api } from "./api/client";

// Import Pages
import Login from "./pages/Login";
import ExecutiveOverview from "./pages/ExecutiveOverview";
import ThreatMap from "./pages/ThreatMap";
import ActiveIncidents from "./pages/ActiveIncidents";
import MitreView from "./pages/MitreView";
import VulnerabilityView from "./pages/VulnerabilityView";
import PredictionView from "./pages/PredictionView";
import DigitalTwinView from "./pages/DigitalTwinView";
import AuditTrailView from "./pages/AuditTrailView";
import UEBADashboard from "./pages/UEBADashboard";
import ThreatIntelligenceCenter from "./pages/ThreatIntelligenceCenter";
import ExecutiveCommandCenter from "./pages/ExecutiveCommandCenter";
import RecycleBin from "./pages/RecycleBin";

// Route Guard to verify JWT tokens
const ProtectedRoute = ({ children }) => {
  const token = api.getToken();
  if (!token) {
    // If not authenticated, redirect to login gateway
    return <Navigate to="/login" replace />;
  }
  return children;
};

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Authentication Gateway */}
        <Route path="/login" element={<Login />} />

        {/* Protected Dashboard Routes */}
        <Route 
          path="/" 
          element={
            <ProtectedRoute>
              <ExecutiveOverview />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/threat-map" 
          element={
            <ProtectedRoute>
              <ThreatMap />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/incidents" 
          element={
            <ProtectedRoute>
              <ActiveIncidents />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/mitre" 
          element={
            <ProtectedRoute>
              <MitreView />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/vulnerabilities" 
          element={
            <ProtectedRoute>
              <VulnerabilityView />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/predictions" 
          element={
            <ProtectedRoute>
              <PredictionView />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/digital-twin" 
          element={
            <ProtectedRoute>
              <DigitalTwinView />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/audit" 
          element={
            <ProtectedRoute>
              <AuditTrailView />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/ueba" 
          element={
            <ProtectedRoute>
              <UEBADashboard />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/threat-intel" 
          element={
            <ProtectedRoute>
              <ThreatIntelligenceCenter />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/command-center" 
          element={
            <ProtectedRoute>
              <ExecutiveCommandCenter />
            </ProtectedRoute>
          } 
        />

        <Route 
          path="/recycle-bin" 
          element={
            <ProtectedRoute>
              <RecycleBin />
            </ProtectedRoute>
          } 
        />

        {/* Fallback Redirection */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
