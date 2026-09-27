import pino, { type Logger } from 'pino';
import { workerEnv } from '../config/env.js';

const isProduction = workerEnv.NODE_ENV === 'production';
const isTest = workerEnv.NODE_ENV === 'test';

const redactPaths = [
  '*.password',
  '*.token',
  '*.accessToken',
  '*.secret',
  '*.apiKey',
  '*.AI_API_KEY',
  '*.MONGO_URI',
  '*.REDIS_URL',
];

export const logger: Logger = pino({
  level: isTest ? 'silent' : workerEnv.LOG_LEVEL,
  base: { service: workerEnv.SERVICE_NAME, env: workerEnv.NODE_ENV },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: redactPaths, censor: '[redacted]' },
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

export function childLogger(bindings: Record<string, unknown>): Logger {
  return logger.child(bindings);
}
