/**
 * MongoDB connection lifecycle.
 *
 * Owns the single mongoose connection for the process: connect on boot, expose
 * readiness, close on shutdown. Models will register themselves against this
 * connection in a later milestone; no schema is defined yet.
 */
import mongoose from 'mongoose';
import type { DependencyCheck } from '@aishield/shared';
import { env, isProduction } from '../config/env.js';
import { childLogger } from '../logging/logger.js';
import { withTimeout } from '../utils/with-timeout.js';

const log = childLogger({ component: 'mongo' });

const PING_TIMEOUT_MS = 2_000;
let listenersRegistered = false;

function registerConnectionEvents(): void {
  if (listenersRegistered) return;
  listenersRegistered = true;

  const connection = mongoose.connection;
  connection.on('error', (error) => log.error({ err: error }, 'MongoDB connection error'));
  connection.on('disconnected', () => log.warn('MongoDB disconnected'));
  connection.on('reconnected', () => log.info('MongoDB reconnected'));
}

export async function connectMongo(uri: string = env.MONGO_URI): Promise<void> {
  mongoose.set('strictQuery', true);
  registerConnectionEvents();

  await mongoose.connect(uri, {
    maxPoolSize: env.MONGO_POOL_SIZE,
    serverSelectionTimeoutMS: 10_000,
    // Index builds are a deployment concern in production, not a boot action.
    autoIndex: !isProduction,
  });

  log.info({ database: mongoose.connection.name }, 'MongoDB connected');
}

export async function checkMongo(): Promise<DependencyCheck> {
  const startedAt = Date.now();

  try {
    const db = mongoose.connection.db;
    if (!db) {
      return { status: 'down', message: 'No active connection' };
    }

    await withTimeout(db.admin().command({ ping: 1 }), PING_TIMEOUT_MS, 'mongo ping');
    return { status: 'up', latencyMs: Date.now() - startedAt };
  } catch (error) {
    return {
      status: 'down',
      latencyMs: Date.now() - startedAt,
      message: error instanceof Error ? error.message : 'Unknown MongoDB error',
    };
  }
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
  log.info('MongoDB disconnected');
}
