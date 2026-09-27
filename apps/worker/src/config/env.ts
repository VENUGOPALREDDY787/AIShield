import 'dotenv/config';
import { z } from 'zod';

const LOG_LEVELS = ['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent'] as const;
const NODE_ENVS = ['development', 'test', 'production'] as const;

export const workerEnvSchema = z.object({
  NODE_ENV: z.enum(NODE_ENVS).default('development'),
  LOG_LEVEL: z.enum(LOG_LEVELS).default('info'),
  SERVICE_NAME: z.string().min(1).default('aishield-worker'),

  MONGO_URI: z.string().min(1).default('mongodb://127.0.0.1:27017/aishield'),
  MONGO_POOL_SIZE: z.coerce.number().int().min(1).max(200).default(10),

  REDIS_URL: z.string().min(1).default('redis://127.0.0.1:6379'),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_TLS: z
    .enum(['true', 'false'])
    .default('false')
    .transform((value) => value === 'true'),

  QUEUE_PREFIX: z.string().min(1).default('aishield'),
  QUEUE_CONCURRENCY: z.coerce.number().int().min(1).max(20).default(2),

  SCANNER_RUNNER: z.enum(['docker', 'local']).default('docker'),
  SCANNER_WORK_DIR: z.string().min(1).default('/tmp/aishield-scans'),
  SCANNER_TIMEOUT_MS: z.coerce.number().int().min(1000).default(300000),

  SEMGREP_RULES: z.string().default('p/security-audit,p/owasp-top-ten'),
  SCANNER_IMAGE_SEMGREP: z.string().default('returntocorp/semgrep:1.78.0'),

  SCANNER_IMAGE_GITLEAKS: z.string().default('zricethezav/gitleaks:v8.18.2'),
  GITLEAKS_CONFIG_PATH: z.string().optional(),

  SCANNER_IMAGE_OSV: z.string().default('ghcr.io/google/osv-scanner:v1.7.0'),
});

export type WorkerEnv = z.infer<typeof workerEnvSchema>;

function loadWorkerEnv(): WorkerEnv {
  const result = workerEnvSchema.safeParse(process.env);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  • ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    console.error(`[worker-config] Invalid environment configuration:\n${details}`);
    process.exit(1);
  }
  return Object.freeze(result.data);
}

export const workerEnv = loadWorkerEnv();
