import { describe, expect, it } from 'vitest';
import vercelConfig from '../vercel.json' with { type: 'json' };
import { checkProductionApiBase, connectSourcesFrom } from './production-api-policy.mjs';

const allowed = connectSourcesFrom(vercelConfig);

describe('production API base policy', () => {
  it('reads connect-src from the committed vercel.json', () => {
    expect(allowed).toContain('https://api-lab.scoutgrid.io');
  });

  it('requires an explicit API base for a Vercel production build', () => {
    expect(() => checkProductionApiBase({ VERCEL_ENV: 'production' }, allowed)).toThrow('must be set');
    expect(() => checkProductionApiBase({ VERCEL_ENV: 'production', VITE_API_BASE: ' ' }, allowed)).toThrow('must be set');
  });

  it('allows unset outside Vercel production, so CI and previews fall back to same-origin /api', () => {
    expect(() => checkProductionApiBase({}, allowed)).not.toThrow();
    expect(() => checkProductionApiBase({ VERCEL_ENV: 'preview' }, allowed)).not.toThrow();
  });

  it('accepts same-origin /api and the CSP-allowed lab API', () => {
    expect(() => checkProductionApiBase({ VERCEL_ENV: 'production', VITE_API_BASE: '/api' }, allowed)).not.toThrow();
    expect(() => checkProductionApiBase({ VERCEL_ENV: 'production', VITE_API_BASE: 'https://api-lab.scoutgrid.io/api/' }, allowed)).not.toThrow();
  });

  it('rejects the retired host, plain http and malformed values', () => {
    expect(() => checkProductionApiBase({ VITE_API_BASE: 'https://api.scoutgrid.io/api' }, allowed)).toThrow('not allowed by connect-src');
    expect(() => checkProductionApiBase({ VITE_API_BASE: 'http://api-lab.scoutgrid.io/api' }, allowed)).toThrow('https');
    expect(() => checkProductionApiBase({ VITE_API_BASE: 'api-lab.scoutgrid.io' }, allowed)).toThrow('/api or an absolute');
  });
});
