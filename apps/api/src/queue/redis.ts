/**
 * Redis connection management.
 *
 * BullMQ needs a raw ioredis client, and the health probe needs to ping the
 * same server, so the process keeps exactly one shared connection. It is
 * created lazily: importing this module must not open a socket (that keeps the
 * test suite hermetic and makes boot order explicit).
 */
import { Redis } from 'ioredis';
import type { DependencyCheck } from '@aishield/shared';
import { env, isDevelopment } from '../config/env.js';
import { childLogger } from '../logging/logger.js';
import { withTimeout } from '../utils/with-timeout.js';

const log = childLogger({ component: 'redis' });
const PING_TIMEOUT_MS = 2_000;

let client: Redis | null = null;
let loggedOfflineWarning = false;

export function getRedisClient(): Redis {
  if (client) return client;

  const created = new Redis(env.REDIS_URL, {
    ...(env.REDIS_PASSWORD ? { password: env.REDIS_PASSWORD } : {}),
    ...(env.REDIS_TLS ? { tls: {} } : {}),
    // BullMQ requires this to be null: it issues blocking commands that must
    // not be aborted by the client's own retry budget.
    maxRetriesPerRequest: null,
    enableReadyCheck: true,
    lazyConnect: true,
    retryStrategy: (attempt) => {
      if (isDevelopment && attempt > 2) {
        // Stop infinite retry loop in local development when Redis is not running
        return null;
      }
      return Math.min(attempt * 200, 5_000);
    },
  });

  created.on('error', (error: Error) => {
    const code = (error as unknown as { code?: string }).code;
    if (isDevelopment && code === 'ECONNREFUSED') {
      if (!loggedOfflineWarning) {
        log.warn('Redis server is not running on 127.0.0.1:6379 — scan queue is in standalone mode.');
        loggedOfflineWarning = true;
      }
      return;
    }
    log.error({ err: error }, 'Redis client error');
  });
  created.on('ready', () => {
    loggedOfflineWarning = false;
    log.info('Redis connection ready');
  });
  created.on('end', () => log.warn('Redis connection closed'));

  client = created;
  return client;
}

export async function connectRedis(): Promise<void> {
  const connection = getRedisClient();
  if (connection.status === 'ready' || connection.status === 'connecting') return;
  await connection.connect();
  log.info('Redis connected');
}

export async function checkRedis(): Promise<DependencyCheck> {
  const startedAt = Date.now();

  try {
    const pong = await withTimeout(getRedisClient().ping(), PING_TIMEOUT_MS, 'redis ping');
    return pong === 'PONG'
      ? { status: 'up', latencyMs: Date.now() - startedAt }
      : { status: 'down', latencyMs: Date.now() - startedAt, message: `Unexpected reply: ${pong}` };
  } catch (error) {
    return {
      status: 'down',
      latencyMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : 'Unknown Redis error',
    };
  }
}

export async function disconnectRedis(): Promise<void> {
  if (!client) return;
  await client.quit().catch(() => client?.disconnect());
  client = null;
  log.info('Redis disconnected');
}
