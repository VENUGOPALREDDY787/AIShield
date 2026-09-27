/**
 * Redis connection management for the worker process.
 *
 * Configured specifically for BullMQ workers:
 * - maxRetriesPerRequest: null (required by BullMQ for blocking commands)
 * - enableReadyCheck: true
 * - lazyConnect: true (avoids socket opening on module import)
 */
import { Redis } from 'ioredis';
import { workerEnv } from '../config/env.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'worker-redis' });

let client: Redis | null = null;

export function getWorkerRedisClient(): Redis {
  if (client) return client;

  client = new Redis(workerEnv.REDIS_URL, {
    ...(workerEnv.REDIS_PASSWORD ? { password: workerEnv.REDIS_PASSWORD } : {}),
    ...(workerEnv.REDIS_TLS ? { tls: {} } : {}),
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    lazyConnect: true,
    retryStrategy: (attempt) => Math.min(attempt * 200, 5_000),
  });

  client.on('error', (err) => log.error({ err }, 'Worker Redis client error'));
  client.on('ready', () => log.info('Worker Redis connection ready'));
  client.on('end', () => log.warn('Worker Redis connection closed'));

  return client;
}

export async function connectWorkerRedis(): Promise<void> {
  const conn = getWorkerRedisClient();
  if (conn.status === 'ready' || conn.status === 'connecting') return;
  await conn.connect();
  log.info('Worker Redis connected');
}

export async function closeWorkerRedis(): Promise<void> {
  if (!client) return;
  try {
    await client.quit();
  } catch {
    client.disconnect();
  } finally {
    client = null;
    log.info('Worker Redis disconnected');
  }
}
