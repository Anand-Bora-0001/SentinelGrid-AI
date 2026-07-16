/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0f172a",       // slate-900
          card: "#1e293b",     // slate-800
          elevated: "#334155", // slate-700
          border: "#475569",   // slate-600
          cyan: "#0284c7",     // sky-600 (more muted blue)
          blue: "#2563eb",     // blue-600
          purple: "#7c3aed",   // violet-600
          success: "#16a34a",  // green-600
          warning: "#ca8a04",  // yellow-600
          orange: "#ea580c",   // orange-600
          danger: "#dc2626",   // red-600
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'cyber-neon': 'none',
        'cyber-neon-purple': 'none',
        'cyber-neon-danger': 'none',
      }
    },
  },
  plugins: [],
}
