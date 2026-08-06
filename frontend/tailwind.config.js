/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0b0f19",
        cardBg: "#111827",
        panelBorder: "#1f2937",
        accentBlue: "#3b82f6",
        accentGreen: "#10b981",
        accentYellow: "#f59e0b",
        accentRed: "#ef4444"
      }
    },
  },
  plugins: [],
}
