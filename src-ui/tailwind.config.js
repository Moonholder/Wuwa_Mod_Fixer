/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content:[
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      keyframes: {
        'bg-pan': {
          '0%': { backgroundPosition: '0% center' },
          '100%': { backgroundPosition: '-200% center' },
        },
        'slide': {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '40px 40px' },
        }
      },
      backgroundSize: {
        '300%': '300%',
      }
    }
  },
  plugins: [],
}
