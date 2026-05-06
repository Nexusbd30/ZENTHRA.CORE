/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 🎨 Paleta ZENTHRA
        background: "#0f172a",   // fondo general (azul oscuro)
        card: "#1e293b",         // gris azulado para tarjetas
        primary: "#2563eb",      // azul corporativo brillante
        secondary: "#38bdf8",    // azul claro (resaltados)
        accent: "#0ea5e9",       // cian complementario
        danger: "#ef4444",       // rojo para alertas
        success: "#22c55e",      // verde para confirmaciones
        warning: "#f59e0b",      // amarillo de advertencia

        // 🩶 Escala de grises personalizada (incluye 950)
        gray: {
          50: "#f9fafb",
          100: "#f3f4f6",
          200: "#e5e7eb",
          300: "#d1d5db",
          400: "#9ca3af",
          500: "#6b7280",
          600: "#4b5563",
          700: "#374151",
          800: "#1f2937",
          900: "#111827",
          950: "#0b0f1a",
        },
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "Roboto", "sans-serif"],
      },
      boxShadow: {
        neon: "0 0 10px #38bdf8, 0 0 20px #2563eb",
      },
      borderRadius: {
        xl: "1rem",
        "2xl": "1.25rem",
      },
    },
  },
  plugins: [],
};
