import { createScanWorker } from './queue/scan-worker.js';
import { workerEnv } from './config/env.js';
import { childLogger } from './logging/logger.js';
import { connectWorkerMongo, disconnectWorkerMongo } from './db/mongo.js';
import { connectWorkerRedis, closeWorkerRedis } from './queue/redis.js';

const log = childLogger({ component: 'worker-main' });

log.info(
  {
    service: workerEnv.SERVICE_NAME,
    concurrency: workerEnv.QUEUE_CONCURRENCY,
    prefix: workerEnv.QUEUE_PREFIX,
  },
  'Starting AIShield Security Analysis Worker...',
);

// Connect dependencies
await connectWorkerMongo();
await connectWorkerRedis();

const worker = createScanWorker();

let isShuttingDown = false;

async function shutdown(signal: string) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  log.info({ signal }, 'Received shutdown signal, gracefully draining worker...');

  try {
    // 1. Close BullMQ worker (stops receiving new jobs and finishes current ones)
    await worker.close();
    log.info('BullMQ worker closed');

    // 2. Disconnect Redis
    await closeWorkerRedis();

    // 3. Disconnect MongoDB
    await disconnectWorkerMongo();

    log.info('Graceful shutdown complete');
    process.exit(0);
  } catch (err) {
    log.error({ err }, 'Error during graceful shutdown');
    process.exit(1);
  }
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
