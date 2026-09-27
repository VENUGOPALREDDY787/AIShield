/**
 * Infrastructure probes.
 *
 * `GET /health`  — liveness. Answers from process memory only: if this endpoint
 *                  fails the process is wedged and should be restarted.
 * `GET /health/ready` — readiness. Pings MongoDB and Redis; a failure means
 *                  "do not route traffic here yet", not "restart me".
 *
 * Both are mounted outside the versioned API so orchestrators never have to
 * track our API version.
 */
import { Router } from 'express';
import type { DependencyCheck, HealthResponse } from '@aishield/shared';
import { SERVICE_VERSION } from '../config/constants.js';
import { env } from '../config/env.js';
import { checkMongo } from '../db/mongo.js';
import { checkRedis } from '../queue/redis.js';

export const healthRouter = Router();

healthRouter.get('/', (_req, res) => {
  const body: HealthResponse = {
    status: 'ok',
    service: env.SERVICE_NAME,
    version: SERVICE_VERSION,
    environment: env.NODE_ENV,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
  };

  res.status(200).json(body);
});

healthRouter.get('/ready', async (_req, res) => {
  // Probed in parallel: total latency is the slowest dependency, not the sum.
  const [mongo, redis] = await Promise.all([checkMongo(), checkRedis()]);
  const checks: Record<string, DependencyCheck> = { mongo, redis };
  const degraded = Object.values(checks).some((check) => check.status === 'down');

  const body: HealthResponse = {
    status: degraded ? 'degraded' : 'ok',
    service: env.SERVICE_NAME,
    version: SERVICE_VERSION,
    environment: env.NODE_ENV,
    uptimeSeconds: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    checks,
  };

  res.status(degraded ? 503 : 200).json(body);
});
