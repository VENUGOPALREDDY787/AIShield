/**
 * Scan queue producer.
 *
 * The API only ever *enqueues* work; the worker process consumes it. Both sides
 * share the queue name and the `QUEUE_PREFIX` namespace from
 * `@aishield/shared`, so `aishield:scan` means the same thing in both processes.
 *
 * No job is enqueued yet — this module exists so the routing layer, the worker
 * and the dashboard can be built against one stable contract.
 */
import { Queue } from 'bullmq';
import { SCAN_QUEUE_NAME, type ScanJobData, type ScanJobResult } from '@aishield/shared';
import { env } from '../config/env.js';
import { childLogger } from '../logging/logger.js';
import { getRedisClient } from './redis.js';

const log = childLogger({ component: 'scan-queue' });

export type ScanQueue = Queue<ScanJobData, ScanJobResult>;

let queue: ScanQueue | null = null;

export function getScanQueue(): ScanQueue {
  if (queue) return queue;

  queue = new Queue<ScanJobData, ScanJobResult>(SCAN_QUEUE_NAME, {
    connection: getRedisClient(),
    // Namespaces every Redis key: `aishield:scan:*`.
    prefix: env.QUEUE_PREFIX,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: 'exponential', delay: 5_000 },
      removeOnComplete: { count: env.QUEUE_REMOVE_ON_COMPLETE },
      removeOnFail: { count: env.QUEUE_REMOVE_ON_FAIL },
    },
  });

  log.debug({ queue: SCAN_QUEUE_NAME, prefix: env.QUEUE_PREFIX }, 'Scan queue initialised');
  return queue;
}

export async function closeScanQueue(): Promise<void> {
  if (!queue) return;
  await queue.close();
  queue = null;
}
