/**
 * Configuration management.
 *
 * Every environment variable the API consumes is declared once, validated once
 * and frozen. Invalid configuration fails the boot with an actionable message
 * instead of surfacing later in an unrelated place. This is the only module in
 * the service allowed to read `process.env`.
 */
import 'dotenv/config';
import { z } from 'zod';

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
const NODE_ENVS = ['development', 'test', 'production'] as const;

/**
 * Developer-friendly fallbacks. They are deliberately loopback addresses, and
 * `superRefine` below refuses to boot a production process that is still using
 * them — so they can never silently become a production default.
 */
const DEV_FALLBACK_MONGO_URI = 'mongodb://127.0.0.1:27017/aishield';
const DEV_FALLBACK_REDIS_URL = 'redis://127.0.0.1:6379';

const csv = (value: string): string[] =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

export const envSchema = z
  .object({
    NODE_ENV: z.enum(NODE_ENVS).default('development'),
    LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
    SERVICE_NAME: z.string().min(1).default('aishield-api'),

    API_HOST: z.string().min(1).default('0.0.0.0'),
    API_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    API_BODY_LIMIT: z.string().min(1).default('1mb'),
    CORS_ORIGINS: z.string().min(1).default('http://localhost:5173'),

    MONGO_URI: z.string().min(1).default(DEV_FALLBACK_MONGO_URI),
    MONGO_POOL_SIZE: z.coerce.number().int().min(1).max(200).default(10),

    REDIS_URL: z.string().min(1).default(DEV_FALLBACK_REDIS_URL),
    REDIS_PASSWORD: z.string().optional(),
    REDIS_TLS: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),

    QUEUE_PREFIX: z.string().min(1).default('aishield'),
    QUEUE_CONCURRENCY: z.coerce.number().int().min(1).max(100).default(4),
    QUEUE_REMOVE_ON_COMPLETE: z.coerce.number().int().min(0).default(500),
    QUEUE_REMOVE_ON_FAIL: z.coerce.number().int().min(0).default(1000),

    /** API authentication key. Min 32 chars to prevent weak keys. */
    API_KEY: z.string().min(32).optional(),
    /** Skip authentication entirely (for local dev without a key configured). */
    SKIP_AUTH: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),
  })
  .superRefine((value, ctx) => {
    if (value.NODE_ENV !== 'production') return;

    if (value.MONGO_URI === DEV_FALLBACK_MONGO_URI) {
      ctx.addIssue({
        code: 'custom',
        path: ['MONGO_URI'],
        message: 'MONGO_URI must be set explicitly when NODE_ENV=production',
      });
    }

    if (value.REDIS_URL === DEV_FALLBACK_REDIS_URL) {
      ctx.addIssue({
        code: 'custom',
        path: ['REDIS_URL'],
        message: 'REDIS_URL must be set explicitly when NODE_ENV=production',
      });
    }

    if (value.CORS_ORIGINS.includes('localhost')) {
      ctx.addIssue({
        code: 'custom',
        path: ['CORS_ORIGINS'],
        message: 'CORS_ORIGINS must not contain localhost when NODE_ENV=production',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  • ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    // The logger is not available yet — it depends on this module.
    console.error(
      `[config] Invalid environment configuration:\n${details}\n\nSee .env.example for the expected variables.`,
    );
    process.exit(1);
  }

  return Object.freeze(result.data);
}

export const env: Env = loadEnv();

export const isProduction = env.NODE_ENV === 'production';
export const isDevelopment = env.NODE_ENV === 'development';
export const isTest = env.NODE_ENV === 'test';

/** Browser origins allowed to call the API. */
export const corsOrigins: readonly string[] = csv(env.CORS_ORIGINS);
