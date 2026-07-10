import React from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

export default function DashboardLayout({ title, children }) {
  return (
    <div className="flex h-screen w-screen bg-cyber-bg overflow-hidden">
      {/* Navigation sidebar */}
      <Sidebar />

      {/* Main dashboard content area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar navigation / status bar */}
        <Topbar title={title} />

        {/* View content panel */}
        <main className="flex-1 overflow-y-auto p-8 relative scanline-effect">
          {children}
        </main>
      </div>
    </div>
  );
}
