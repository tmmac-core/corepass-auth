import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 10000,
  },
  // Prevent Vite from pre-bundling @noble/curves (optional dep, lazy-loaded)
  optimizeDeps: {
    exclude: ['@noble/curves'],
  },
});
