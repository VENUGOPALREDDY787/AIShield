import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { REQUEST_ID_HEADER } from '../config/constants.js';
import { logger } from '../logging/logger.js';

/**
 * Assigns every request a correlation id and a child logger bound to it.
 *
 * Runs before pino-http so the HTTP logger reuses the same id, and before the
 * routes so handlers can log with `req.logger`. An inbound `x-request-id` (set
 * by a gateway or an upstream service) is trusted to preserve end-to-end trace
 * continuity; otherwise a fresh UUID is minted.
 */
export function requestContext(req: Request, res: Response, next: NextFunction): void {
  const inbound = req.headers[REQUEST_ID_HEADER];
  const requestId = (Array.isArray(inbound) ? inbound[0] : inbound)?.trim() || randomUUID();

  req.requestId = requestId;
  req.logger = logger.child({ requestId });
  res.setHeader(REQUEST_ID_HEADER, requestId);

  next();
}
