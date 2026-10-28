import { describe, expect, it } from 'vitest';
import { coverageLabel, ecosystemLabel, fixTypeLabel, safePercent, severityClass, titleCase } from './format';

describe('fix intelligence formatting', () => {
  it('never produces NaN or more than 100%', () => {
    expect(safePercent(Number.NaN)).toBe(0);
    expect(safePercent(140)).toBe(100);
    expect(safePercent(null)).toBe(0);
    expect(coverageLabel(5, 4, 125)).toBe('5 / 4 (100%)');
    expect(coverageLabel(0, 0, null)).toBe('No assets');
  });

  it('labels enum values', () => {
    expect(ecosystemLabel('CROSS_PLATFORM')).toBe('Cross-platform');
    expect(ecosystemLabel(null)).toBe('Unknown');
    expect(fixTypeLabel('COMPENSATING_CONTROL')).toBe('Compensating control');
    expect(titleCase('PENDING_REBOOT')).toBe('Pending Reboot');
    expect(severityClass('CRITICAL')).toContain('severity-critical');
    expect(severityClass(null)).toContain('fi-severity-none');
  });
});
