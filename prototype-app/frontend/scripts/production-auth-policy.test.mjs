import { describe, expect, it } from 'vitest';
import { rejectProductionAuthenticationInputs, staticAuthenticationVariables } from './production-auth-policy.mjs';

describe('production authentication input policy', () => {
  it('rejects arbitrary credential and JWT values without echoing them', () => {
    for (const name of staticAuthenticationVariables) {
      for (const value of ['arbitrary-secret-sentinel', ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJzZW50aW5lbCJ9', 'c2lnbmF0dXJl'].join('.')]) {
        expect(() => rejectProductionAuthenticationInputs({ [name]: value })).toThrow(name);
        try {
          rejectProductionAuthenticationInputs({ [name]: value });
        } catch (error) {
          expect(error.message).not.toContain(value);
        }
      }
    }
    expect(() => rejectProductionAuthenticationInputs({ VITE_API_KEY: ' ', VITE_API_BASE: 'https://app.example/api' })).not.toThrow();
  });
});
