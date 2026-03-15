import { build } from 'esbuild';
import { mkdirSync } from 'fs';

// Ensure output directories exist
mkdirSync('dist/esm', { recursive: true });
mkdirSync('dist/cjs', { recursive: true });

// Bundle the widget as a self-contained IIFE
await build({
  entryPoints: ['src/widget/widget.ts'],
  bundle: true,
  minify: true,
  format: 'iife',
  globalName: 'CorePassWidget',
  target: ['es2020', 'chrome80', 'firefox80', 'safari14'],
  // Output to both ESM and CJS dist directories
  outfile: 'dist/esm/widget.js',
  define: {
    'process.env.NODE_ENV': '"production"',
  },
});

// Copy to CJS dist as well
import { copyFileSync } from 'fs';
copyFileSync('dist/esm/widget.js', 'dist/cjs/widget.js');

console.log('Widget bundle built: dist/esm/widget.js + dist/cjs/widget.js');
