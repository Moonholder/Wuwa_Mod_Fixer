import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [
    vue(),
  ],
  resolve: {
    alias: { 
      '@': resolve(__dirname, './src'),
      'vue-i18n': 'vue-i18n/dist/vue-i18n.esm-bundler.js'
    }
  },
  define: {
    __VUE_I18N_FULL_INSTALL__: true,
    __VUE_I18N_LEGACY_API__: false,
    __INTLIFY_PROD_DEVTOOLS__: false,
  },
  // Tauri dev server
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] }
  },
  // Don't open browser (Tauri handles the window)
  build: {
    target: 'esnext',
    minify: 'esbuild',
    cssCodeSplit: true,
    chunkSizeWarningLimit: 500,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
  esbuild: {
    drop: process.env.TAURI_DEBUG ? [] : ['console', 'debugger'],
  },
  envPrefix: ['VITE_', 'TAURI_'],
})
