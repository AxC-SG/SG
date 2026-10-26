import { describe, expect, it } from 'vitest';
import { formatTimestamp, timeAgo } from './time';

function isoOffsetMs(ms: number): string {
  return new Date(Date.now() - ms).toISOString();
}

describe('timeAgo', () => {
  it('returns null for undefined input', () => {
    expect(timeAgo(undefined)).toBeNull();
  });

  it('returns "just now" for timestamps less than 1 minute ago', () => {
    expect(timeAgo(isoOffsetMs(30_000))).toBe('just now');
  });

  it('returns minutes ago for timestamps under 1 hour', () => {
    expect(timeAgo(isoOffsetMs(5 * 60_000))).toBe('5 min ago');
  });

  it('returns hours ago for timestamps under 24 hours', () => {
    expect(timeAgo(isoOffsetMs(3 * 3_600_000))).toBe('3 hr ago');
  });

  it('returns singular day for exactly 1 day ago', () => {
    expect(timeAgo(isoOffsetMs(24 * 3_600_000 + 1000))).toBe('1 day ago');
  });

  it('returns plural days for multiple days ago', () => {
    expect(timeAgo(isoOffsetMs(3 * 24 * 3_600_000 + 1000))).toBe('3 days ago');
  });
});

describe('formatTimestamp', () => {
  it('returns "-" for undefined', () => {
    expect(formatTimestamp(undefined)).toBe('-');
  });

  it('returns "-" for null', () => {
    expect(formatTimestamp(null)).toBe('-');
  });

  it('returns "-" for empty string', () => {
    expect(formatTimestamp('')).toBe('-');
  });

  it('returns the raw value for an unparseable string', () => {
    expect(formatTimestamp('not-a-date')).toBe('not-a-date');
  });

  it('returns a locale-formatted string for a valid ISO timestamp', () => {
    const iso = '2026-01-15T10:30:00.000Z';
    const result = formatTimestamp(iso);
    expect(result).not.toBe('-');
    expect(result).not.toBe(iso);
    expect(typeof result).toBe('string');
  });
});
