/**
 * API process entry point.
 *
 * Boot order is deliberate: dependencies first, then the socket. A process that
 * cannot reach MongoDB or Redis should never accept traffic — it would fail
 * every request it is handed.
 */
import type { Server } from 'node:http';
import { createApp } from './app.js';
import { API_PREFIX, HEALTH_PREFIX, SHUTDOWN_TIMEOUT_MS } from './config/constants.js';
import { env } from './config/env.js';
import { connectMongo, disconnectMongo } from './db/mongo.js';
import { logger } from './logging/logger.js';
import { closeScanQueue } from './queue/scan-queue.js';
import { connectRedis, disconnectRedis } from './queue/redis.js';

async function bootstrap(): Promise<void> {
  await connectMongo();
  await connectRedis();

  const app = createApp();

  const server = app.listen(env.API_PORT, env.API_HOST, () => {
    logger.info(
      {
        host: env.API_HOST,
        port: env.API_PORT,
        health: `${HEALTH_PREFIX}/ready`,
        api: API_PREFIX,
      },
      'AIShield Debt API listening',
    );
  });

  registerShutdownHandlers(server);
}

function registerShutdownHandlers(server: Server): void {
  let shuttingDown = false;

  const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info({ signal }, 'Shutdown signal received — draining connections');

    // Hard deadline: never let a stuck connection block a container restart.
    const forceExit = setTimeout(() => {
      logger.error('Graceful shutdown timed out — forcing exit');
      process.exit(1);
    }, SHUTDOWN_TIMEOUT_MS);
    forceExit.unref();

    try {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await closeScanQueue();
      await disconnectRedis();
      await disconnectMongo();

      clearTimeout(forceExit);
      logger.info('Shutdown complete');
      process.exit(0);
    } catch (error) {
      logger.error({ err: error }, 'Error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', (signal) => void shutdown(signal));
  process.on('SIGINT', (signal) => void shutdown(signal));

  process.on('unhandledRejection', (reason) => {
    logger.error({ err: reason }, 'Unhandled promise rejection');
  });

  process.on('uncaughtException', (error) => {
    // The process is in an unknown state; log and let the orchestrator replace it.
    logger.fatal({ err: error }, 'Uncaught exception — exiting');
    process.exit(1);
  });
}

bootstrap().catch((error: unknown) => {
  logger.fatal({ err: error }, 'Failed to start the API');
  process.exit(1);
});
