/** Small async helpers shared by the infrastructure adapters. */

export class TimeoutError extends Error {
  constructor(operation: string, timeoutMs: number) {
    super(`Operation "${operation}" did not complete within ${timeoutMs}ms`);
    this.name = 'TimeoutError';
  }
}

/**
 * Rejects if `promise` does not settle within `timeoutMs`.
 *
 * Used by health probes: a dependency that hangs is as unhealthy as one that
 * refuses the connection, and a probe must always answer.
 */
export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation = 'operation',
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new TimeoutError(operation, timeoutMs)), timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
