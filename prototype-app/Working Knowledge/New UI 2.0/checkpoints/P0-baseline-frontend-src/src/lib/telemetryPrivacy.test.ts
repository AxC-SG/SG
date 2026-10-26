import { describe, expect, it } from 'vitest';
import type { ErrorEvent } from '@sentry/react';
import { privateTelemetryOptions, scrubTelemetryBreadcrumb, scrubTelemetryEvent, telemetryPath } from './telemetryPrivacy';

describe('telemetry privacy boundary', () => {
  const sentinel = 'private-sentinel-value';
  it('removes bearer paths, fragments, query strings, origins and encoded copies', () => {
    for (const url of [
      `https://app.example/invite/${sentinel}?email=person@example.test#${sentinel}`,
      `/tenant-invite#token=${sentinel}`, `/setup/${encodeURIComponent(sentinel)}?email=person@example.test`,
      `/setup#token=${sentinel}&email=person@example.test`, `/api/tenant-invites/${sentinel}/accept`,
    ]) {
      expect(telemetryPath(url)).not.toContain(sentinel);
      expect(telemetryPath(url)).not.toContain('@');
      expect(telemetryPath(url)).not.toContain('app.example');
    }
    expect(telemetryPath('/findings?filter=test')).toBe('/findings');
  });
  it('discards arbitrary nested and cyclic copies, request headers/body/referrer and error text', () => {
    const extra: Record<string, unknown> = { nested: { token: sentinel }, secret: sentinel };
    extra.self = extra;
    const event = {
      type: undefined,
      message: `Failed ${sentinel}`, logentry: { message: sentinel }, tags: { secret: sentinel }, extra,
      user: { email: 'person@example.test', id: sentinel }, contexts: { custom: extra },
      request: { url: `/invite/${sentinel}#token=${sentinel}`, headers: { Authorization: sentinel, Referer: `/setup/${sentinel}` }, data: extra },
      exception: { values: [{ type: sentinel, value: `Failed ${sentinel}`, stacktrace: { frames: [{ filename: `/setup/${sentinel}`, function: sentinel, context_line: sentinel }] } }] },
      breadcrumbs: [{ category: 'http', message: sentinel, data: { url: `/api/tenant-invites/${sentinel}`, body: extra, email: 'person@example.test' } }],
    } as ErrorEvent;
    const output = JSON.stringify(scrubTelemetryEvent(event));
    expect(output).not.toContain(sentinel);
    expect(output).not.toContain('person@example.test');
    expect(output).not.toContain('Authorization');
    expect(scrubTelemetryEvent(event).exception?.values?.[0].value).toBe('Error details redacted');
  });
  it('retains bounded diagnostics and keeps telemetry disabled without a DSN', () => {
    expect(privateTelemetryOptions('', 'production').enabled).toBe(false);
    expect(privateTelemetryOptions(undefined, 'test').enabled).toBe(false);
    expect(privateTelemetryOptions('https://public@example.test/1', 'production').sendDefaultPii).toBe(false);
    expect(scrubTelemetryBreadcrumb({ category: 'console', message: sentinel })).toBeNull();
    expect(scrubTelemetryBreadcrumb({ category: 'api', data: { method: 'POST', status: 401, path: `/setup#${sentinel}` } })?.data)
      .toEqual({ method: 'POST', status: 401, path: '/setup' });
  });
});
