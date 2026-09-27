/**
 * In-memory sliding-window rate limiter.
 *
 * Limits requests per IP address (or a custom key) within a rolling time window.
 * The store is garbage-collected by a periodic sweep so the Map cannot grow
 * without bound under sustained attack.
 *
 * Production note: for multi-instance deployments, replace this with a Redis
 * sliding-window implementation backed by the existing ioredis connection. The
 * interface (`createRateLimiter`) is designed so the implementation can be swapped
 * transparently.
 *
 * Rate limit headers follow the draft IETF standard:
 *   RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset, Retry-After
 */
import type { Request, Response, NextFunction } from 'express';
import { RateLimitError } from '../errors/app-error.js';

interface WindowEntry {
  count: number;
  windowStart: number;
}

export interface RateLimitOptions {
  /** Maximum requests allowed per window. */
  maxRequests: number;
  /** Window duration in milliseconds. */
  windowMs: number;
  /** Returns the rate-limit key for a request. Defaults to client IP. */
  keyExtractor?: (req: Request) => string;
  /** Error message returned when the limit is exceeded. */
  message?: string;
  /** Whether to add standard rate-limit headers. Defaults to true. */
  headers?: boolean;
}

/**
 * Creates an Express middleware that rate-limits requests by the configured key.
 *
 * @example
 * // 200 requests per minute globally
 * app.use(createRateLimiter({ maxRequests: 200, windowMs: 60_000 }));
 *
 * // 10 scan submissions per minute, keyed by authenticated user
 * scanRouter.post('/', createRateLimiter({
 *   maxRequests: 10,
 *   windowMs: 60_000,
 *   keyExtractor: (req) => req.auth?.userId ?? req.ip ?? 'anon',
 * }));
 */
export function createRateLimiter(options: RateLimitOptions) {
  const store = new Map<string, WindowEntry>();
  const {
    maxRequests,
    windowMs,
    message = 'Too many requests, please try again later',
    headers = true,
  } = options;

  // Periodic cleanup prevents memory growth from abandoned clients
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of store.entries()) {
      if (now - entry.windowStart > windowMs) {
        store.delete(key);
      }
    }
  }, Math.min(windowMs, 60_000));

  // Don't prevent the process from exiting if only the timer is active
  if (cleanup.unref) cleanup.unref();

  return function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): void {
    const keyExtractor = options.keyExtractor ?? ((r: Request) => r.ip ?? 'unknown');
    const key = keyExtractor(req);
    const now = Date.now();

    let entry = store.get(key);
    if (!entry || now - entry.windowStart > windowMs) {
      entry = { count: 0, windowStart: now };
      store.set(key, entry);
    }

    entry.count++;

    if (headers) {
      const resetAt = Math.ceil((entry.windowStart + windowMs) / 1000);
      const remaining = Math.max(maxRequests - entry.count, 0);
      res.setHeader('X-RateLimit-Limit', maxRequests);
      res.setHeader('X-RateLimit-Remaining', remaining);
      res.setHeader('X-RateLimit-Reset', resetAt);
    }

    if (entry.count > maxRequests) {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      next(new RateLimitError(message));
      return;
    }

    next();
  };
}

/** General API rate limit: 200 requests per minute per IP. */
export const globalRateLimit = createRateLimiter({
  maxRequests: 200,
  windowMs: 60_000,
});

/** Stricter limit for operations that enqueue scan jobs. */
export const scanSubmitRateLimit = createRateLimiter({
  maxRequests: 10,
  windowMs: 60_000,
  message: 'Too many scan submissions — please wait before submitting another scan',
});

/** Relaxed limit for read-heavy dashboard endpoints. */
export const dashboardReadRateLimit = createRateLimiter({
  maxRequests: 300,
  windowMs: 60_000,
});
