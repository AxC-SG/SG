// VITE_API_BASE names the backend. Unset, the app calls its own origin's /api: the Vite
// proxy in development, and the same-origin artifact in browser fixture builds. Vercel
// production builds must set it (scripts/production-api-policy.mjs enforces this).
export function resolveApiBase(apiBase = import.meta.env.VITE_API_BASE): string {
  const configured = apiBase?.trim();
  return configured ? configured.replace(/\/+$/, '') : '/api';
}
