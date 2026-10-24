import '@testing-library/jest-dom/vitest';

// Node 26 exposes Web Storage globals independently of jsdom. Always use a
// deterministic browser-like store for these isolated mock tests.
const testStorage = new Map<string, string>();
const storage: Storage = {
  get length() { return testStorage.size; },
  clear: () => testStorage.clear(),
  getItem: key => testStorage.get(key) ?? null,
  setItem: (key, value) => { testStorage.set(key, String(value)); },
  removeItem: key => { testStorage.delete(key); },
  key: index => [...testStorage.keys()][index] ?? null,
};
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
Object.defineProperty(window, 'localStorage', { configurable: true, value: storage });

// jsdom has no ResizeObserver and no real layout engine (elements always measure 0x0).
// @xyflow/react (AiDependencyGraph) waits for a ResizeObserver callback with a non-zero
// contentRect before it will render nodes/edges, so the stub must actually invoke it.
class ResizeObserverStub {
  private callback: ResizeObserverCallback;
  constructor(callback: ResizeObserverCallback) {
    this.callback = callback;
  }
  observe(target: Element) {
    queueMicrotask(() => {
      this.callback(
        [{
          target,
          contentRect: { width: 800, height: 420 },
          borderBoxSize: [{ inlineSize: 800, blockSize: 420 }],
          contentBoxSize: [{ inlineSize: 800, blockSize: 420 }],
        } as unknown as ResizeObserverEntry],
        this as unknown as ResizeObserver,
      );
    });
  }
  unobserve() {}
  disconnect() {}
}
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
}

// jsdom also has no DOMMatrixReadOnly, which @xyflow/react uses to read a node's current
// transform scale when positioning edges/handles.
class DOMMatrixReadOnlyStub {
  m22: number;
  constructor(transform?: string) {
    const scale = transform?.match(/scale\(([^)]+)\)/)?.[1];
    this.m22 = scale ? Number(scale) : 1;
  }
}
if (typeof globalThis.DOMMatrixReadOnly === 'undefined') {
  globalThis.DOMMatrixReadOnly = DOMMatrixReadOnlyStub as unknown as typeof DOMMatrixReadOnly;
}
