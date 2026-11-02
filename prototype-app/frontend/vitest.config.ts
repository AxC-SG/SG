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
      // Ratcheted 2026-10-29 after Stage 4 Workbench tab, draft and guard tests.
      // Two-worker run: lines 55.16%, statements 52.73%, functions 44.3%, branches 43.81%.
      thresholds: {
        lines: 58.7,
        statements: 56.1,
        functions: 48.2,
        branches: 48.1
      }
    }
  }
}));
