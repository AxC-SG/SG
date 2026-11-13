import { describe, expect, it } from 'vitest';
import { resolveApiBase } from './base';

describe('resolveApiBase', () => {
  it('uses same-origin /api when no override is present', () => {
    expect(resolveApiBase('')).toBe('/api');
    expect(resolveApiBase(undefined)).toBe('/api');
  });

  it('never falls back to the retired api.scoutgrid.io host', () => {
    expect(resolveApiBase('')).not.toContain('api.scoutgrid.io');
  });

  it('preserves an explicit env override and trims trailing slashes', () => {
    expect(resolveApiBase('http://localhost:8080/api/')).toBe('http://localhost:8080/api');
    expect(resolveApiBase('https://api.example.com/base///')).toBe('https://api.example.com/base');
  });
});
