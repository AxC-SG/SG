import { vi } from 'vitest';

/** jsdom has no layout engine — every element measures 0x0 via getBoundingClientRect,
 * which makes @xyflow/react treat every node as zero-sized and skip rendering it.
 * Scoped per-test (not global setup) so it can't affect unrelated pages' layout-sensitive
 * behavior; restore with vi.restoreAllMocks() in the calling test's afterEach. */
export function mockElementDimensionsForReactFlow(): void {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 800, height: 420, top: 0, left: 0, right: 800, bottom: 420, x: 0, y: 0,
    toJSON() { return this; },
  });
}
