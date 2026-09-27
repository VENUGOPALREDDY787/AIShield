import type { ErrorRequestHandler } from 'express';
import { ZodError } from 'zod';
import type { ApiErrorBody } from '@aishield/shared';
import { isAppError } from '../errors/app-error.js';
import { ERROR_CODES, type ErrorCode } from '../errors/error-codes.js';
import { isProduction } from '../config/env.js';

interface NormalizedError {
  statusCode: number;
  code: ErrorCode;
  message: string;
  details?: unknown;
  /** True when the failure was expected rather than a defect. */
  operational: boolean;
  cause: unknown;
}

/** Body parsing failures raised by `express.json()` carry these markers. */
interface BodyParserError extends Error {
  type?: string;
  status?: number;
  statusCode?: number;
}

function isBodyParserError(error: unknown): error is BodyParserError {
  return (
    error instanceof Error &&
    'type' in error &&
    typeof (error as BodyParserError).type === 'string' &&
    (error as BodyParserError).type!.startsWith('entity.')
  );
}

/**
 * Maps anything thrown in the request lifecycle onto one shape. Unknown errors
 * are assumed to be defects: logged with their stack, reported as a generic 500
 * so internals never leak to a client.
 */
function normalize(error: unknown): NormalizedError {
  if (isAppError(error)) {
    return {
      statusCode: error.statusCode,
      code: error.code,
      message: error.message,
      details: error.details,
      operational: error.isOperational,
      cause: error.cause ?? error,
    };
  }

  if (error instanceof ZodError) {
    return {
      statusCode: 422,
      code: ERROR_CODES.VALIDATION_ERROR,
      message: 'Request validation failed',
      details: error.issues.map((issue) => ({
        path: issue.path.join('.'),
        message: issue.message,
      })),
      operational: true,
      cause: error,
    };
  }

  if (isBodyParserError(error)) {
    return {
      statusCode: 400,
      code: ERROR_CODES.BAD_REQUEST,
      message: 'Malformed request body',
      operational: true,
      cause: error,
    };
  }

  // Mongoose surfaces cast/validation problems as `name`-tagged errors.
  if (error instanceof Error && error.name === 'CastError') {
    return {
      statusCode: 400,
      code: ERROR_CODES.BAD_REQUEST,
      message: 'Malformed identifier or field value',
      operational: true,
      cause: error,
    };
  }

  return {
    statusCode: 500,
    code: ERROR_CODES.INTERNAL_ERROR,
    message: 'Internal server error',
    operational: false,
    cause: error,
  };
}

/**
 * Centralized error handler — the only place in the service that writes an
 * error response. Must be registered last and must keep all four parameters so
 * Express recognises it as an error handler.
 */
export const errorHandler: ErrorRequestHandler = (error, req, res, _next) => {
  const normalized = normalize(error);

  if (normalized.operational) {
    req.logger?.warn(
      { code: normalized.code, statusCode: normalized.statusCode, err: normalized.cause },
      normalized.message,
    );
  } else {
    req.logger?.error({ code: normalized.code, err: normalized.cause }, 'Unhandled exception');
  }

  if (res.headersSent) {
    // The response already started streaming; the only correct action is to
    // abort so the client sees a truncated response instead of a corrupted one.
    req.logger?.error('Error raised after response headers were sent — destroying socket');
    res.destroy();
    return;
  }

  // Defensive: details of an unexpected failure may contain internal state, so
  // only operational (expected) errors expose them in production.
  const mayExposeDetails = normalized.operational || !isProduction;

  const body: ApiErrorBody = {
    error: {
      code: normalized.code,
      message: normalized.message,
      ...(mayExposeDetails && normalized.details !== undefined
        ? { details: normalized.details }
        : {}),
      requestId: req.requestId,
    },
  };

  res.status(normalized.statusCode).json(body);
};
