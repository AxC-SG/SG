import { describe, expect, it } from 'vitest';
import { resolveApiBase } from './base';

describe('resolveApiBase', () => {
  it('uses the dev proxy when no local env override is present', () => {
    expect(resolveApiBase('', false)).toBe('/api');
  });

  it('uses the deployed backend when no production env override is present', () => {
    expect(resolveApiBase('', true)).toBe('https://api.scoutgrid.io/api');
  });

  it('preserves an explicit env override and trims trailing slashes', () => {
    expect(resolveApiBase('http://localhost:8080/api/')).toBe('http://localhost:8080/api');
    expect(resolveApiBase('https://api.example.com/base///')).toBe('https://api.example.com/base');
  });
});
