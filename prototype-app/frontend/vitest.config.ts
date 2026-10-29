import { configDefaults, defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

export default mergeConfig(viteConfig, defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.ts',
    // Browser checks under e2e/ run through Playwright, not vitest.
    exclude: [...configDefaults.exclude, 'e2e/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.test.{ts,tsx}',
        'src/**/*.spec.{ts,tsx}',
        'src/test/**',
        'src/main.tsx',
        'src/vite-env.d.ts',
        'src/**/*.d.ts',
      ],
      // Global line-coverage floor. Ratchet up as page/widget tests are added.
      // Ratcheted 2026-10-29 after Stage 1b state-adoption coverage.
      // Two-worker run: lines 53.48%, statements 50.76%, functions 42.64%, branches 42.33%.
      thresholds: {
        lines: 54.1,
        statements: 51.5,
        functions: 43.3,
        branches: 42.9
      }
    }
  }
}));
