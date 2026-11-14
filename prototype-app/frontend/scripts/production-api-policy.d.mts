// Types for production-api-policy.mjs, which vite.config.ts imports under strict type checking.

export interface VercelConfig {
  headers?: Array<{ headers?: Array<{ key: string; value: string }> }>;
}

export function connectSourcesFrom(vercelConfig: VercelConfig): string[];

export function checkProductionApiBase(
  environment: Record<string, string | undefined>,
  connectSources: string[],
): void;
