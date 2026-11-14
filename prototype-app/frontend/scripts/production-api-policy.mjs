import { URL } from 'node:url';

// Build-time check for the backend address baked into the bundle. A Vercel production
// build must name its API explicitly: the old built-in fallback pointed at a retired host.
// Any configured address must be same-origin (/api) or an HTTPS origin the served CSP
// allows in connect-src, otherwise the browser would block every API call.

export function connectSourcesFrom(vercelConfig) {
  for (const route of vercelConfig.headers ?? []) {
    for (const header of route.headers ?? []) {
      if (header.key.toLowerCase() !== 'content-security-policy') continue;
      const directive = header.value.split(';').map((part) => part.trim())
        .find((part) => part.startsWith('connect-src '));
      if (directive) return directive.split(/\s+/).slice(1);
    }
  }
  return [];
}

export function checkProductionApiBase(environment, connectSources) {
  const apiBase = environment.VITE_API_BASE?.trim() ?? '';
  if (!apiBase) {
    if (environment.VERCEL_ENV === 'production') {
      throw new Error('VITE_API_BASE must be set for a production deployment.');
    }
    return;
  }
  if (apiBase === '/api') return;

  let url;
  try {
    url = new URL(apiBase);
  } catch {
    throw new Error('VITE_API_BASE must be /api or an absolute https:// URL.');
  }
  if (url.protocol !== 'https:') {
    throw new Error('VITE_API_BASE must use https.');
  }
  if (!connectSources.includes(url.origin)) {
    throw new Error(`VITE_API_BASE origin ${url.origin} is not allowed by connect-src in vercel.json.`);
  }
}
