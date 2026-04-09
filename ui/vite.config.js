import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build output goes straight into the Go embed directory.
// During development: npm run dev proxies /api/* to the running monitor.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/graphapi/static',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom'],
          'graph-vendor': ['cytoscape', 'cytoscape-dagre'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:9090',
        changeOrigin: true,
      },
    },
  },
})
