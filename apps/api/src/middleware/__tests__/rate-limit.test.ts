/**
 * Tests for rate limiting middleware.
 */
import { describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { createRateLimiter } from '../rate-limit.js';
import { RateLimitError } from '../../errors/app-error.js';

describe('createRateLimiter', () => {
  it('allows requests within limit and attaches rate limit headers', () => {
    const limiter = createRateLimiter({ maxRequests: 5, windowMs: 60_000 });
    const headers: Record<string, unknown> = {};
    const req = { ip: '127.0.0.1' } as Request;
    const res = {
      setHeader: vi.fn((key, val) => {
        headers[key] = val;
      }),
    } as unknown as Response;
    const next = vi.fn();

    limiter(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', 5);
    expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', 4);
  });

  it('blocks requests exceeding limit with RateLimitError and Retry-After header', () => {
    const limiter = createRateLimiter({ maxRequests: 2, windowMs: 10_000 });
    const req = { ip: '192.168.1.100' } as Request;
    const res = { setHeader: vi.fn() } as unknown as Response;

    // 1st request - ok
    limiter(req, res, vi.fn());
    // 2nd request - ok
    limiter(req, res, vi.fn());

    // 3rd request - rate limited
    const next3 = vi.fn();
    limiter(req, res, next3);

    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', 10);
    expect(next3).toHaveBeenCalledWith(expect.any(RateLimitError));
  });
});
