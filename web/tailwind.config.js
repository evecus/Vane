/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Vane brand colors
        vane: {
          50:  '#f0f4ff',
          100: '#e0e9ff',
          200: '#c7d6fe',
          300: '#a5b8fc',
          400: '#8191f8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
        },
        // Module accent colors
        forward: { light: '#3b82f6', dark: '#1d4ed8', bg: '#eff6ff' },
        ddns:    { light: '#10b981', dark: '#059669', bg: '#ecfdf5' },
        web:     { light: '#8b5cf6', dark: '#7c3aed', bg: '#f5f3ff' },
        cert:    { light: '#f59e0b', dark: '#d97706', bg: '#fffbeb' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' },
        },
        glow: {
          from: { boxShadow: '0 0 10px rgba(99, 102, 241, 0.4)' },
          to:   { boxShadow: '0 0 25px rgba(99, 102, 241, 0.8), 0 0 50px rgba(99, 102, 241, 0.3)' },
        },
        slideIn: {
          from: { opacity: '0', transform: 'translateY(10px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
      },
      backdropBlur: { xs: '2px' },
      boxShadow: {
        'glass': '0 8px 32px rgba(0, 0, 0, 0.1), inset 0 1px 0 rgba(255,255,255,0.2)',
        'card':  '0 4px 24px rgba(0, 0, 0, 0.06), 0 1px 4px rgba(0, 0, 0, 0.04)',
        'card-hover': '0 12px 40px rgba(0, 0, 0, 0.12), 0 4px 12px rgba(0, 0, 0, 0.06)',
        'colored-blue':   '0 8px 24px rgba(59, 130, 246, 0.25)',
        'colored-green':  '0 8px 24px rgba(16, 185, 129, 0.25)',
        'colored-purple': '0 8px 24px rgba(139, 92, 246, 0.25)',
        'colored-amber':  '0 8px 24px rgba(245, 158, 11, 0.25)',
      }
    },
  },
  plugins: [],
}
