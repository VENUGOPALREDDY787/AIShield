import { ERROR_CODES, type ErrorCode } from './error-codes.js';

export interface AppErrorOptions {
  statusCode?: number;
  code?: ErrorCode;
  /** Extra machine-readable context. Never include secrets or internal paths. */
  details?: unknown;
  cause?: unknown;
}

/**
 * Base class for every error the API raises deliberately.
 *
 * `isOperational` distinguishes expected failures (bad input, missing record)
 * from programmer errors. The centralized handler logs the two at different
 * levels and only the operational ones are considered safe to expose.
 */
export class AppError extends Error {
  readonly statusCode: number;
  readonly code: ErrorCode;
  readonly isOperational: boolean;
  readonly details?: unknown;

  constructor(message: string, options: AppErrorOptions = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.statusCode = options.statusCode ?? 500;
    this.code = options.code ?? ERROR_CODES.INTERNAL_ERROR;
    this.details = options.details;
    this.isOperational = true;
    Error.captureStackTrace?.(this, new.target);
  }
}

export class BadRequestError extends AppError {
  constructor(message = 'Malformed request', options: AppErrorOptions = {}) {
    super(message, { statusCode: 400, code: ERROR_CODES.BAD_REQUEST, ...options });
  }
}

export class ValidationError extends AppError {
  constructor(message = 'Request validation failed', options: AppErrorOptions = {}) {
    super(message, { statusCode: 422, code: ERROR_CODES.VALIDATION_ERROR, ...options });
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found', options: AppErrorOptions = {}) {
    super(message, { statusCode: 404, code: ERROR_CODES.NOT_FOUND, ...options });
  }
}

export class ConflictError extends AppError {
  constructor(message = 'Resource conflict', options: AppErrorOptions = {}) {
    super(message, { statusCode: 409, code: ERROR_CODES.CONFLICT, ...options });
  }
}

export class NotImplementedError extends AppError {
  constructor(message = 'Not implemented yet', options: AppErrorOptions = {}) {
    super(message, { statusCode: 501, code: ERROR_CODES.NOT_IMPLEMENTED, ...options });
  }
}

export class DependencyUnavailableError extends AppError {
  constructor(message = 'Upstream dependency unavailable', options: AppErrorOptions = {}) {
    super(message, { statusCode: 503, code: ERROR_CODES.DEPENDENCY_UNAVAILABLE, ...options });
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Authentication required', options: AppErrorOptions = {}) {
    super(message, { statusCode: 401, code: ERROR_CODES.UNAUTHORIZED, ...options });
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Access denied', options: AppErrorOptions = {}) {
    super(message, { statusCode: 403, code: ERROR_CODES.FORBIDDEN, ...options });
  }
}

export class RateLimitError extends AppError {
  constructor(message = 'Too many requests', options: AppErrorOptions = {}) {
    super(message, { statusCode: 429, code: ERROR_CODES.RATE_LIMITED, ...options });
  }
}

/** Narrowing helper used by the centralized error handler. */
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}
