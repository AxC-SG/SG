// Column preference storage for DataTable. Only explicit user actions write; viewport and default
// computation never do. Legacy keys (`storageKey` widths, `:order`, `:hidden`) stay readable.

export type ColumnPriority = 'essential' | 'default' | 'optional';

export type VisibilityOverride = { visible: boolean; provenance: 'user' | 'legacy-snapshot' };

export type ColumnPreferencesV2 = {
  version: 2;
  visibilityOverrides: Record<string, VisibilityOverride>;
};

export type PreferenceColumn = {
  id: string;
  priority?: ColumnPriority;
  defaultHidden?: boolean;
};

const ORDER_SUFFIX = ':order';
const HIDDEN_SUFFIX = ':hidden';
const PREFERENCES_SUFFIX = ':preferences:v2';

function readJson(key: string): unknown {
  try {
    const raw = window.localStorage.getItem(key);
    return raw == null ? undefined : JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function writeJson(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // no-op for storage failures
  }
}

function readIdList(key: string): string[] | null {
  const parsed = readJson(key);
  if (!Array.isArray(parsed)) return null;
  return parsed.map((value) => String(value)).filter((value) => value.length > 0);
}

// Numeric-looking ids keep the legacy numeric serialization so existing stored orders still match.
function serializeIds(ids: string[]): Array<number | string> {
  return ids.map((id) => {
    const numeric = Number(id);
    return Number.isInteger(numeric) && String(numeric) === id ? numeric : id;
  });
}

export function readStoredWidths(storageKey: string): Record<string, number> {
  const parsed = readJson(storageKey);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const next: Record<string, number> = {};
  Object.entries(parsed).forEach(([key, value]) => {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric > 0) next[key] = Math.round(numeric);
  });
  return next;
}

export function writeStoredWidths(storageKey: string, widths: Record<string, number>): void {
  writeJson(storageKey, widths);
}

export function readStoredOrder(storageKey: string): string[] | null {
  const order = readIdList(`${storageKey}${ORDER_SUFFIX}`);
  return order && order.length > 0 ? order : null;
}

export function writeStoredOrder(storageKey: string, order: string[]): void {
  writeJson(`${storageKey}${ORDER_SUFFIX}`, serializeIds(order));
}

function isOverride(value: unknown): value is VisibilityOverride {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.visible === 'boolean'
    && (candidate.provenance === 'user' || candidate.provenance === 'legacy-snapshot');
}

function readV2(storageKey: string): ColumnPreferencesV2 | null {
  const parsed = readJson(`${storageKey}${PREFERENCES_SUFFIX}`);
  if (!parsed || typeof parsed !== 'object') return null;
  const candidate = parsed as Record<string, unknown>;
  if (candidate.version !== 2 || !candidate.visibilityOverrides || typeof candidate.visibilityOverrides !== 'object') return null;
  const overrides: Record<string, VisibilityOverride> = {};
  Object.entries(candidate.visibilityOverrides as Record<string, unknown>).forEach(([id, value]) => {
    if (isOverride(value)) overrides[id] = { visible: value.visible, provenance: value.provenance };
  });
  return { version: 2, visibilityOverrides: overrides };
}

// The old table wrote a visibility snapshot on every mount, so a snapshot is not evidence of intent.
// Import both visible and hidden choices for the columns the snapshot knew about (its stored order),
// so newer columns still receive current defaults.
export function readVisibilityOverrides(storageKey: string, columns: PreferenceColumn[]): Record<string, VisibilityOverride> {
  const v2 = readV2(storageKey);
  if (v2) return v2.visibilityOverrides;
  const hidden = readIdList(`${storageKey}${HIDDEN_SUFFIX}`);
  if (hidden == null) return {};
  const hiddenIds = new Set(hidden);
  const knownIds = new Set(readStoredOrder(storageKey) ?? columns.map((column) => column.id));
  const overrides: Record<string, VisibilityOverride> = {};
  columns.forEach((column) => {
    if (knownIds.has(column.id)) {
      overrides[column.id] = { visible: !hiddenIds.has(column.id), provenance: 'legacy-snapshot' };
    }
  });
  return overrides;
}

export function writeVisibilityOverrides(storageKey: string, overrides: Record<string, VisibilityOverride>): void {
  const value: ColumnPreferencesV2 = { version: 2, visibilityOverrides: overrides };
  writeJson(`${storageKey}${PREFERENCES_SUFFIX}`, value);
}

// Reset clears widths, order, the legacy snapshot and v2 overrides; it never touches filters or other settings.
export function clearColumnPreferences(storageKey: string): void {
  try {
    [storageKey, `${storageKey}${ORDER_SUFFIX}`, `${storageKey}${HIDDEN_SUFFIX}`, `${storageKey}${PREFERENCES_SUFFIX}`]
      .forEach((key) => window.localStorage.removeItem(key));
  } catch {
    // no-op for storage failures
  }
}

export function defaultVisible(column: PreferenceColumn, narrow: boolean): boolean {
  if (column.priority === 'essential') return true;
  if (column.defaultHidden) return false;
  return !(narrow && column.priority === 'optional');
}

// Essential columns always render; explicit overrides win over responsive defaults.
export function resolveVisibility(
  columns: PreferenceColumn[],
  overrides: Record<string, VisibilityOverride>,
  narrow: boolean,
): Record<string, boolean> {
  const next: Record<string, boolean> = {};
  columns.forEach((column) => {
    const override = overrides[column.id];
    next[column.id] = column.priority === 'essential' || (override ? override.visible : defaultVisible(column, narrow));
  });
  if (columns.length > 0 && columns.every((column) => !next[column.id])) {
    next[columns[0].id] = true;
  }
  return next;
}

export function reconcileOrder(order: string[] | null, columns: PreferenceColumn[]): string[] {
  const currentIds = columns.map((column) => column.id);
  if (!order) return currentIds;
  const valid = new Set(currentIds);
  const next = order.filter((id) => valid.has(id));
  currentIds.forEach((id) => {
    if (!next.includes(id)) next.push(id);
  });
  return next;
}

// Rendered widths never go below a column's declared minimum. Spare container width goes to columns
// without a user width (or the last column) so a resized column keeps its size; overflow scrolls.
export function layoutWidths(
  visibleIds: string[],
  minWidths: Record<string, number>,
  baseWidths: Record<string, number | undefined>,
  userWidths: Record<string, number>,
  containerWidth: number,
): Record<string, number> {
  const widths: Record<string, number> = {};
  visibleIds.forEach((id) => {
    const min = minWidths[id];
    widths[id] = Math.max(min, Math.round(userWidths[id] ?? baseWidths[id] ?? min));
  });
  const total = visibleIds.reduce((sum, id) => sum + widths[id], 0);
  const spare = Math.floor(containerWidth) - total;
  if (spare <= 0 || visibleIds.length === 0) return widths;

  const flexible = visibleIds.filter((id) => userWidths[id] == null);
  const targets = flexible.length > 0 ? flexible : [visibleIds[visibleIds.length - 1]];
  const targetTotal = targets.reduce((sum, id) => sum + widths[id], 0);
  let remaining = spare;
  targets.forEach((id, index) => {
    const share = index === targets.length - 1 ? remaining : Math.floor((spare * widths[id]) / targetTotal);
    widths[id] += share;
    remaining -= share;
  });
  return widths;
}

export function moveId(order: string[], id: string, offset: -1 | 1, isVisible: (id: string) => boolean): string[] {
  const visible = order.filter(isVisible);
  const position = visible.indexOf(id);
  const neighbor = visible[position + offset];
  if (position < 0 || neighbor == null) return order;
  const next = order.filter((value) => value !== id);
  const neighborIndex = next.indexOf(neighbor);
  next.splice(offset < 0 ? neighborIndex : neighborIndex + 1, 0, id);
  return next;
}

export function moveBefore(order: string[], sourceId: string, targetId: string): string[] {
  const fromIndex = order.indexOf(sourceId);
  const toIndex = order.indexOf(targetId);
  if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex) return order;
  const next = [...order];
  const [moved] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, moved);
  return next;
}
