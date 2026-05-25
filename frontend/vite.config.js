import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // All /api/* calls are forwarded to FastAPI — no CORS needed in dev
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  build: {
    // Split the previously-monolithic 1.14 MB bundle by dependency family.
    // Heavy viz libs (recharts, force-graph) only download when an analyst
    // opens Dashboard or Investigation; framer-motion stays a separate
    // chunk so the landing-page paint isn't blocked by it.
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'charts': ['recharts'],
          'graph': ['react-force-graph-2d'],
          'motion': ['framer-motion'],
          'icons': ['lucide-react'],
          'toast': ['react-hot-toast'],
        },
      },
    },
    // Raise the per-chunk warning threshold a touch — the new chunks are all
    // legitimately a few hundred KB of vendor code we want cached separately.
    chunkSizeWarningLimit: 700,
  },
})
