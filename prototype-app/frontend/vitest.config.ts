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
      // Ratcheted 2026-10-25 after direct Findings HTTP contract coverage.
      // Two-worker run: lines 49.71%, statements 47.22%, functions 39.52%, branches 38.67%.
      thresholds: {
        lines: 49.7,
        statements: 47.2,
        functions: 39.5,
        branches: 38.6
      }
    }
  }
}));
