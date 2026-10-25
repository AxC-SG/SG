import type { Breadcrumb, BrowserOptions, ErrorEvent } from '@sentry/react';

// Only route vocabulary is useful for telemetry. Dynamic identifiers, every
// query/fragment, origins, and legacy bearer path segments are discarded.
const routeWords = new Set([
  'api', 'auth', 'login', 'setup', 'setup-password', 'setup-session', 'invite', 'tenant-invite',
  'demo-invites', 'tenant-invites', 'validate', 'accept', 'demo-requests', 'findings', 'inventory',
  'assets', 'connect', 'platform', 'tenants', 'admin', 'users', 'policies', 'exposure', 'vuln-repo',
  'org-cves', 'vulnerabilities', 'campaigns', 'configurations', 'operations', 'cve-detail', 'me',
]);

export function telemetryPath(value: string): string {
  try {
    const path = new URL(value, 'https://telemetry.invalid').pathname;
    return path.split('/').map((segment) => {
      if (!segment) return '';
      try {
        const decoded = decodeURIComponent(segment);
        return routeWords.has(decoded) ? decoded : '[redacted]';
      } catch {
        return '[redacted]';
      }
    }).join('/');
  } catch {
    return '[redacted]';
  }
}

export function scrubTelemetryBreadcrumb(crumb: Breadcrumb): Breadcrumb | null {
  const category = crumb.category;
  if (!category || !['navigation', 'http', 'fetch', 'xhr', 'api', 'performance'].includes(category)) return null;
  const data: Record<string, string | number> = {};
  // Read only known scalars; arbitrary nested/cyclic values are never traversed.
  for (const key of ['url', 'from', 'to', 'path']) {
    const value: unknown = crumb.data?.[key];
    if (typeof value === 'string') data[key] = telemetryPath(value);
  }
  for (const key of ['status_code', 'status', 'durationMs', 'value']) {
    const value: unknown = crumb.data?.[key];
    if (typeof value === 'number' && Number.isFinite(value)) data[key] = value;
  }
  const method: unknown = crumb.data?.method;
  if (typeof method === 'string' && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(method)) data.method = method;
  return { category, message: `${category} event`, data, timestamp: typeof crumb.timestamp === 'number' ? crumb.timestamp : undefined };
}

export function scrubTelemetryEvent(event: ErrorEvent): ErrorEvent {
  // Construct an allowlisted envelope. Removing only named credential fields
  // would leave copies inside error text, contexts, tags, headers and extra data.
  return {
    type: undefined,
    platform: 'javascript',
    event_id: event.event_id && /^[a-f0-9]{32}$/.test(event.event_id) ? event.event_id : undefined,
    timestamp: typeof event.timestamp === 'number' ? event.timestamp : undefined,
    level: event.level,
    exception: event.exception ? {
      values: event.exception.values?.map((exception) => ({
        type: 'Error',
        value: 'Error details redacted',
        stacktrace: exception.stacktrace ? {
          frames: exception.stacktrace.frames?.map((frame) => ({
            filename: frame.filename ? telemetryPath(frame.filename) : undefined,
            lineno: typeof frame.lineno === 'number' ? frame.lineno : undefined,
            colno: typeof frame.colno === 'number' ? frame.colno : undefined,
            in_app: frame.in_app,
          })),
        } : undefined,
      })),
    } : undefined,
    request: event.request ? {
      url: event.request.url ? telemetryPath(event.request.url) : undefined,
    } : undefined,
    breadcrumbs: event.breadcrumbs?.map(scrubTelemetryBreadcrumb).filter((crumb): crumb is Breadcrumb => crumb !== null),
  };
}

export function privateTelemetryOptions(dsn: string | undefined, mode: string): BrowserOptions {
  return {
    dsn,
    enabled: Boolean(dsn?.trim()),
    environment: mode,
    sendDefaultPii: false,
    // Keep error capture, but remove automatic DOM/console/request breadcrumbs
    // and raw browser request/referrer collection before they enter the scope.
    integrations: (defaults) => defaults.filter((integration) => !['Breadcrumbs', 'HttpContext'].includes(integration.name)),
    beforeBreadcrumb: scrubTelemetryBreadcrumb,
    beforeSend: scrubTelemetryEvent,
    beforeSendTransaction: () => null,
    beforeSendLog: () => null,
    beforeSendMetric: () => null,
  };
}
