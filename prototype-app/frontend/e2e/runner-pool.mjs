// Bound independent journey processes; await every result before reporting errors.
export async function runPool(items, concurrency, run) {
  if (!Number.isInteger(concurrency) || concurrency < 1) throw new Error('Journey workers must be a positive integer');
  let cursor = 0;
  const errors = [];
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      try {
        await run(items[index]);
      } catch (error) {
        errors.push(error);
      }
    }
  }));
  if (errors.length) throw new AggregateError(errors, 'Journey execution failed');
}
