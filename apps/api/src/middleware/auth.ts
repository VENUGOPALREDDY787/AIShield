/**
 * Authentication middleware.
 *
 * Validates API-key credentials from Authorization Bearer or x-api-key header.
 * Uses timing-safe comparison to prevent length-oracle timing attacks.
 *
 * Security properties:
 *  - Timing-safe comparison prevents credential-length oracle attacks
 *  - No token value is ever logged; only a truncated hash for correlation
 *  - The auth context type is shared with the Express Request augmentation
 *
 * Authentication flow:
 *  1. Extract token from `Authorization: Bearer <token>` or `x-api-key: <token>`
 *  2. If API_KEY not configured: allow in development/SKIP_AUTH mode, block in production
 *  3. Validate token against configured API_KEY with timing-safe comparison
 *  4. Set req.auth on success
 */
import { timingSafeEqual, createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import { env, isDevelopment, isTest } from '../config/env.js';
import { UnauthorizedError } from '../errors/app-error.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'auth' });

/** Compare two strings in constant time to prevent timing attacks. */
function timingSafeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still run a comparison on padded input to avoid variable-length timing leak
    const padded = b.padEnd(a.length, '\0');
    timingSafeEqual(Buffer.from(a), Buffer.from(padded));
    return false;
  }
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Extract the Bearer token or x-api-key from request headers. */
function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token.length > 0) return token;
  }
  const apiKey = req.headers['x-api-key'];
  if (typeof apiKey === 'string' && apiKey.length > 0) {
    return apiKey.trim();
  }
  return null;
}

/**
 * Express middleware that authenticates every incoming request.
 * Must be mounted after CORS/helmet and before business routers.
 */
export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  try {
    // Exclude documentation and openapi specs from mandatory auth
    if (req.path === '/docs' || req.path === '/openapi.json' || req.path.endsWith('/openapi.json')) {
      return next();
    }

    const configuredKey = env.API_KEY;
    const skipAuth = env.SKIP_AUTH;

    // Development/test bypass: no key configured and running in dev/test or SKIP_AUTH
    if (!configuredKey) {
      if (isDevelopment || isTest || skipAuth) {
        req.auth = { userId: 'dev-user', role: 'admin', method: 'dev-bypass' };
        return next();
      }
      // Production without a configured key — block all requests
      throw new UnauthorizedError('API authentication is not configured; set API_KEY');
    }

    const token = extractToken(req);
    if (!token) {
      throw new UnauthorizedError(
        'Authentication required: provide a Bearer token or x-api-key header',
      );
    }

    if (!timingSafeStringEqual(token, configuredKey)) {
      // Log only a short hash to correlate replay attacks without exposing the credential
      const tokenHash = createHash('sha256').update(token).digest('hex').slice(0, 8);
      log.warn({ tokenHash }, 'Authentication failed: invalid API key');
      throw new UnauthorizedError('Invalid API key');
    }

    req.auth = { userId: 'api-key-user', role: 'admin', method: 'api-key' };
    next();
  } catch (err) {
    next(err);
  }
}
