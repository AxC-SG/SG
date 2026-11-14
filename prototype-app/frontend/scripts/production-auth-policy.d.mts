// Types for production-auth-policy.mjs, which vite.config.ts imports under strict type checking.

export const staticAuthenticationVariables: readonly string[];

export function rejectProductionAuthenticationInputs(environment: Record<string, string | undefined>): void;
