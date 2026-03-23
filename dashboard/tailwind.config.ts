import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        "primary": "#2463eb",
        "primary-dark": "#1d4ed8",
        "secondary": "#1e293b",
        "background-light": "#f8fafc",
        "background-dark": "#0f172a",
        "muted-blue": "#475569",
        "border-light": "#e2e8f0",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        severity: {
          critical: "#ef4444",
          high:     "#f97316",
          medium:   "#f59e0b",
          low:      "#10b981",
          info:     "#64748b",
        },
        nexus: {
          cyan:   "#06b6d4",
          purple: "#8b5cf6",
          pink:   "#ec4899",
          indigo: "#6366f1",
          teal:   "#14b8a6",
        },
      },
      borderRadius: {
        lg: "0.375rem",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        "full": "9999px",
        "xl": "0.5rem",
        "DEFAULT": "0.25rem"
      },
      fontFamily: {
        sans: ["var(--font-inter)", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "Cascadia Code", "Fira Code", "monospace"],
        "display": ["Inter", "sans-serif"]
      },
      fontSize: {
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to:   { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to:   { height: "0" },
        },
        "fade-in": {
          from: { opacity: "0", transform: "translateY(6px)" },
          to:   { opacity: "1", transform: "translateY(0)" },
        },
        shimmer: {
          "0%":   { backgroundPosition: "-400px 0" },
          "100%": { backgroundPosition:  "400px 0" },
        },
        "pulse-slow": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.4" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up":   "accordion-up 0.2s ease-out",
        "fade-in":        "fade-in 0.2s ease-out",
        shimmer:          "shimmer 1.6s linear infinite",
        "pulse-slow":     "pulse-slow 2.5s ease-in-out infinite",
      },
      boxShadow: {
        glow:        "0 0 20px rgba(59,130,246,0.12)",
        "glow-sm":   "0 0 10px rgba(59,130,246,0.08)",
        "glow-cyan": "0 0 20px rgba(6,182,212,0.12)",
        "glow-red":  "0 0 20px rgba(239,68,68,0.12)",
      },
    },
  },
  plugins: [tailwindcssAnimate],
};

export default config;
