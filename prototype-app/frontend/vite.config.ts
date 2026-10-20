import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { rejectProductionAuthenticationInputs } from './scripts/production-auth-policy.mjs';

export default defineConfig({
  plugins: [react(), {
    name: 'production-authentication-policy',
    configResolved(config) {
      if (config.command === 'build' && config.isProduction) {
        rejectProductionAuthenticationInputs(loadEnv(config.mode, config.envDir, 'VITE_'));
      }
    },
  }],
  server: {
    // Local activation emails use this IPv4 loopback address.
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
});
