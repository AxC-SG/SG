import type { FixView } from './types';

export const FIX_VIEWS: Array<{ key: FixView; label: string }> = [
  { key: 'all', label: 'All Fixes' },
  { key: 'patches', label: 'Patches' },
  { key: 'workarounds', label: 'Workarounds' },
  { key: 'compensating-controls', label: 'Compensating Controls' }
];

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const;
export const ECOSYSTEM_ORDER = ['LINUX', 'CROSS_PLATFORM', 'WINDOWS', 'MACOS'] as const;

const ECOSYSTEM_LABELS: Record<string, string> = {
  WINDOWS: 'Windows',
  LINUX: 'Linux',
  MACOS: 'macOS',
  CROSS_PLATFORM: 'Cross-platform'
};

const FIX_TYPE_LABELS: Record<string, string> = {
  PATCH: 'Patch',
  UPGRADE: 'Upgrade',
  WORKAROUND: 'Workaround',
  CONFIGURATION_CHANGE: 'Configuration change',
  COMPENSATING_CONTROL: 'Compensating control',
  NO_FIX: 'No fix'
};

const PROVIDER_LABELS: Record<string, string> = {
  SCCM: 'SCCM',
  INTUNE: 'Intune',
  BIGFIX: 'BigFix',
  TANIUM: 'Tanium',
  ANALYST: 'Analyst',
  VENDOR_INTELLIGENCE: 'Vendor',
  REFERENCE: 'Reference',
  AI: 'AI',
  PATCH_TOOL: 'Patch tool'
};

export function viewLabel(view: FixView): string {
  return FIX_VIEWS.find((item) => item.key === view)?.label ?? 'All Fixes';
}

export function ecosystemLabel(value: string | null | undefined): string {
  return value ? ECOSYSTEM_LABELS[value] ?? value : 'Unknown';
}

export function fixTypeLabel(value: string | null | undefined): string {
  return value ? FIX_TYPE_LABELS[value] ?? value : 'Unknown';
}

export function providerLabel(value: string | null | undefined): string {
  return value ? PROVIDER_LABELS[value] ?? value : 'Unknown';
}

export function titleCase(value: string | null | undefined): string {
  if (!value) return '—';
  return value.toLowerCase().split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

export function severityClass(severity: string | null | undefined): string {
  switch (severity) {
    case 'CRITICAL': return 'severity-pill severity-critical';
    case 'HIGH': return 'severity-pill severity-high';
    case 'MEDIUM': return 'severity-pill severity-medium';
    case 'LOW': return 'severity-pill severity-low';
    default: return 'severity-pill fi-severity-none';
  }
}

/** "3 / 4 (75%)", or "No assets" when nothing applies — never NaN or over 100%. */
export function coverageLabel(remediated: number, applicable: number, percent: number | null): string {
  if (!applicable || percent == null) return 'No assets';
  return `${remediated} / ${applicable} (${Math.min(100, Math.max(0, percent))}%)`;
}

/** A bar width that is always a finite 0–100. */
export function safePercent(value: number | null | undefined): number {
  if (value == null || !Number.isFinite(value)) return 0;
  return Math.min(100, Math.max(0, value));
}

export function isControlType(fixType: string): boolean {
  return fixType === 'WORKAROUND' || fixType === 'CONFIGURATION_CHANGE' || fixType === 'COMPENSATING_CONTROL';
}
