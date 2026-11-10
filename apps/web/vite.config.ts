import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // No inline scripts anywhere: CSP has no 'unsafe-inline' and Trusted Types are enforced.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    target: 'es2022',
  },
  worker: { format: 'es' },
});
