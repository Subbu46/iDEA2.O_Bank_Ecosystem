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
          dark: '#030712',       // Pure Space Dark
          card: 'rgba(17, 24, 39, 0.75)', // Glass Card
          border: 'rgba(55, 65, 81, 0.4)', // Faint Border
          glow: '#06b6d4',       // Neon Cyan
          toxic: '#f43f5e',      // Cyber Rose/Red
          safe: '#10b981',       // Cyber Emerald
          warning: '#f59e0b'     // Cyber Amber
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', 'sans-serif'],
      },
      boxShadow: {
        'glow-cyan': '0 0 15px rgba(6, 182, 212, 0.3)',
        'glow-red': '0 0 15px rgba(244, 63, 94, 0.4)'
      }
    },
  },
  plugins: [],
}
