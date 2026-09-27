import type { NextFunction, Request, Response } from 'express';
import { NotFoundError } from '../errors/app-error.js';

/**
 * Terminal middleware for unmatched routes. It does not respond itself: it
 * converts the miss into the same error shape as every other failure so the
 * centralized handler remains the single place that writes error bodies.
 */
export function notFoundHandler(req: Request, _res: Response, next: NextFunction): void {
  next(new NotFoundError(`No route matches ${req.method} ${req.originalUrl}`, { details: { method: req.method, path: req.originalUrl } }));
}
