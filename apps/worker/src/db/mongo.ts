/**
 * MongoDB connection lifecycle for the security worker process.
 */
import mongoose from 'mongoose';
import { workerEnv } from '../config/env.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'worker-mongo' });

let listenersRegistered = false;

function registerConnectionEvents(): void {
  if (listenersRegistered) return;
  listenersRegistered = true;

  const connection = mongoose.connection;
  connection.on('error', (error) => log.error({ err: error }, 'Worker MongoDB connection error'));
  connection.on('disconnected', () => log.warn('Worker MongoDB disconnected'));
  connection.on('reconnected', () => log.info('Worker MongoDB reconnected'));
}

export async function connectWorkerMongo(uri: string = workerEnv.MONGO_URI): Promise<void> {
  if (mongoose.connection.readyState === 1) {
    return;
  }

  mongoose.set('strictQuery', true);
  registerConnectionEvents();

  try {
    await mongoose.connect(uri, {
      maxPoolSize: workerEnv.MONGO_POOL_SIZE,
      serverSelectionTimeoutMS: 5_000,
    });
    log.info({ database: mongoose.connection.name }, 'Worker MongoDB connected');
  } catch (err) {
    log.warn({ err }, 'Worker MongoDB connection failed (operating in decoupled mode if DB unavailable)');
  }
}

export function isMongoConnected(): boolean {
  return mongoose.connection.readyState === 1;
}

export async function disconnectWorkerMongo(): Promise<void> {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    log.info('Worker MongoDB disconnected');
  }
}
