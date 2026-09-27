/**
 * Structured logging.
 *
 * One pino instance per process: JSON in production (machine-readable, ships
 * straight to a log pipeline), human-readable in development. Sensitive fields
 * are redacted at the logger level so no call site has to remember to strip
 * them.
 */
import pino, { type Logger } from 'pino';
import { env, isProduction, isTest } from '../config/env.js';

const redactPaths = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  '*.password',
  '*.passwordHash',
  '*.token',
  '*.accessToken',
  '*.refreshToken',
  '*.apiKey',
  '*.secret',
  '*.MONGO_URI',
  '*.REDIS_URL',
  '*.AI_API_KEY',
];

export const logger: Logger = pino({
  level: isTest ? 'silent' : env.LOG_LEVEL,
  base: { service: env.SERVICE_NAME, env: env.NODE_ENV },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: redactPaths, censor: '[redacted]' },
  // A transport runs the formatter in a worker thread. Production must emit
  // raw JSON, and tests must not pay for (or hang on) a worker thread.
  ...(isProduction || isTest
    ? {}
    : {
        transport: {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'SYS:HH:MM:ss.l',
            ignore: 'pid,hostname,service,env',
          },
        },
      }),
});

/** Logger carrying a stable binding for a long-lived subsystem. */
export function childLogger(bindings: Record<string, unknown>): Logger {
  return logger.child(bindings);
}
