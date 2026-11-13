import { readFileSync } from 'node:fs';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { checkProductionApiBase, connectSourcesFrom } from './scripts/production-api-policy.mjs';
import { rejectProductionAuthenticationInputs } from './scripts/production-auth-policy.mjs';

export default defineConfig({
  // Scan the app entry rather than generated coverage/preview HTML. Include the
  // portal entry explicitly so opening a lazy route cannot invalidate React's
  // optimized dependencies underneath an already-open browser session.
  optimizeDeps: {
    entries: ['index.html'],
    include: ['react', 'react-dom', 'react-dom/client', 'react/jsx-runtime'],
  },
  plugins: [react(), {
    name: 'production-authentication-policy',
    configResolved(config) {
      if (config.command === 'build' && config.isProduction) {
        const environment = loadEnv(config.mode, config.envDir, 'VITE_');
        rejectProductionAuthenticationInputs(environment);
        const vercelConfig = JSON.parse(readFileSync(new URL('./vercel.json', import.meta.url), 'utf8'));
        checkProductionApiBase({ ...environment, VERCEL_ENV: process.env.VERCEL_ENV }, connectSourcesFrom(vercelConfig));
      }
    },
  }],
  server: {
    // Local activation emails use this IPv4 loopback address.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    watch: { ignored: ['**/coverage/**'] },
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
});
