const PRODUCTION_API_BASE = 'https://api.scoutgrid.io/api';

export function resolveApiBase(
  apiBase = import.meta.env.VITE_API_BASE,
  production = import.meta.env.PROD,
): string {
  const configured = apiBase?.trim();
  if (configured) {
    return configured.replace(/\/+$/, '');
  }
  return production ? PRODUCTION_API_BASE : '/api';
}
