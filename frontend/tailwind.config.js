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
          bg: "#0a0e17",       // Deep navy-black base
          card: "#111827",     // Dark card surface
          elevated: "#1a2235", // Elevated panels/modals
          border: "#1e293b",   // Subtle borders
          cyan: "#06b6d4",     // Primary action/interactive
          blue: "#3b82f6",     // Secondary accent
          purple: "#8b5cf6",   // AI/ML engine color
          success: "#22c55e",  // Low risk
          warning: "#eab308",  // Medium risk
          orange: "#f97316",   // High risk
          danger: "#ef4444",   // Critical risk
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'cyber-neon': '0 0 15px rgba(6, 182, 212, 0.15)',
        'cyber-neon-purple': '0 0 15px rgba(139, 92, 246, 0.15)',
        'cyber-neon-danger': '0 0 15px rgba(239, 68, 68, 0.2)',
      }
    },
  },
  plugins: [],
}
