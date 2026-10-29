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
      // Ratcheted 2026-10-29 after AsyncSection/MetricValue coverage.
      // Two-worker run: lines 53.43%, statements 50.74%, functions 42.54%, branches 42.17%.
      thresholds: {
        lines: 53.3,
        statements: 50.6,
        functions: 42.4,
        branches: 42.1
      }
    }
  }
}));
