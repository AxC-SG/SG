import React from 'react';
import * as Sentry from '@sentry/react';
import { useLocation } from 'react-router-dom';
import { telemetryPath } from './telemetryPrivacy';

type PerformanceMetricDetail = {
  metric: string;
  value: number;
  unit: 'ms' | 'score';
  context?: Record<string, string | number | boolean>;
};

declare global {
  interface Window {
    __scoutPerformanceMetrics__?: PerformanceMetricDetail[];
  }
}

function recordMetric(detail: PerformanceMetricDetail) {
  if (typeof window !== 'undefined') {
    const buffer = window.__scoutPerformanceMetrics__ ?? [];
    buffer.push(detail);
    if (buffer.length > 100) {
      buffer.shift();
    }
    window.__scoutPerformanceMetrics__ = buffer;
    window.dispatchEvent(new CustomEvent('scout:performance-metric', { detail }));
  }

  Sentry.addBreadcrumb({
    category: 'performance',
    level: 'info',
    message: `${detail.metric}=${detail.value}${detail.unit}`,
    data: detail.context
  });
}

function observeWebVitals() {
  if (typeof PerformanceObserver === 'undefined') {
    return () => undefined;
  }

  const observers: PerformanceObserver[] = [];

  try {
    const lcpObserver = new PerformanceObserver((list) => {
      const entries = list.getEntries();
      const entry = entries[entries.length - 1];
      if (!entry) return;
      recordMetric({ metric: 'LCP', value: Math.round(entry.startTime), unit: 'ms' });
    });
    lcpObserver.observe({ type: 'largest-contentful-paint', buffered: true });
    observers.push(lcpObserver);
  } catch {
    // Ignore unsupported entry types.
  }

  try {
    let clsValue = 0;
    const clsObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries() as Array<PerformanceEntry & { value?: number; hadRecentInput?: boolean }>) {
        if (!entry.hadRecentInput) {
          clsValue += entry.value ?? 0;
        }
      }
      recordMetric({ metric: 'CLS', value: Number(clsValue.toFixed(4)), unit: 'score' });
    });
    clsObserver.observe({ type: 'layout-shift', buffered: true });
    observers.push(clsObserver);
  } catch {
    // Ignore unsupported entry types.
  }

  try {
    const inpObserver = new PerformanceObserver((list) => {
      for (const entry of list.getEntries() as Array<PerformanceEntry & { duration?: number }>) {
        recordMetric({ metric: 'INP-ish', value: Math.round(entry.duration ?? 0), unit: 'ms' });
      }
    });
    inpObserver.observe({ type: 'event', buffered: true, durationThreshold: 16 } as PerformanceObserverInit);
    observers.push(inpObserver);
  } catch {
    // Ignore unsupported entry types.
  }

  return () => {
    observers.forEach((observer) => observer.disconnect());
  };
}

function useRouteTiming() {
  const location = useLocation();

  React.useEffect(() => {
    if (typeof performance === 'undefined') {
      return;
    }
    const safePath = telemetryPath(location.pathname);
    const routeKey = `route:${safePath}`;
    performance.mark(`${routeKey}:start`);
    const frame = requestAnimationFrame(() => {
      performance.mark(`${routeKey}:paint`);
      performance.measure(routeKey, `${routeKey}:start`, `${routeKey}:paint`);
      const entries = performance.getEntriesByName(routeKey, 'measure');
      const latest = entries[entries.length - 1];
      if (latest) {
        recordMetric({
          metric: 'route-transition',
          value: Math.round(latest.duration),
          unit: 'ms',
          context: { path: safePath }
        });
      }
      performance.clearMarks(`${routeKey}:start`);
      performance.clearMarks(`${routeKey}:paint`);
      performance.clearMeasures(routeKey);
    });
    return () => cancelAnimationFrame(frame);
  }, [location.pathname, location.search]);
}

export function PerformanceInstrumentation() {
  useRouteTiming();

  React.useEffect(() => observeWebVitals(), []);
  return null;
}
