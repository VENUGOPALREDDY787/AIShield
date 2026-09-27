/**
 * Express application assembly.
 *
 * `createApp()` builds the middleware pipeline and returns the app without
 * binding a port, so tests can exercise it through supertest and the bootstrap
 * in `index.ts` owns the listening socket. Middleware order is significant and
 * is documented inline.
 */
import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { API_PREFIX, HEALTH_PREFIX } from './config/constants.js';
import { corsOrigins, env, isTest } from './config/env.js';
import { logger } from './logging/logger.js';
import { errorHandler } from './middleware/error-handler.js';
import { notFoundHandler } from './middleware/not-found.js';
import { requestContext } from './middleware/request-context.js';
import { authenticate } from './middleware/auth.js';
import { globalRateLimit } from './middleware/rate-limit.js';
import { healthRouter } from './routes/health.routes.js';
import { apiRouter } from './routes/index.js';

export function createApp(): Express {
  const app = express();

  // Do not advertise the framework.
  app.disable('x-powered-by');
  // Behind a load balancer: trust one hop so `req.ip` and `req.protocol` are real.
  app.set('trust proxy', 1);

  // 1. Correlation id + request-scoped logger. Must come first so every later
  //    layer (including the HTTP logger and the error handler) can use them.
  app.use(requestContext);

  // 2. Access logging.
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => req.requestId,
      // Noisy and useless under test, and it would drown the assertions' output.
      autoLogging: !isTest,
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
      customSuccessMessage: (req, res) => `${req.method} ${req.url} → ${res.statusCode}`,
    }),
  );

  // 3. Security headers and CORS, before anything can produce a response.
  app.use(helmet());
  app.use(
    cors({
      origin: [...corsOrigins],
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
      // Let browsers read the correlation id for bug reports.
      exposedHeaders: ['x-request-id'],
    }),
  );

  // 4. Body parsing, capped so a large payload cannot exhaust memory.
  app.use(express.json({ limit: env.API_BODY_LIMIT }));
  app.use(express.urlencoded({ extended: false, limit: env.API_BODY_LIMIT }));

  // 5. Unauthenticated infrastructure probes (mounted before rate limiting / auth gates)
  app.use(HEALTH_PREFIX, healthRouter);

  // 6. Security Gates: rate limiting and authentication
  app.use(globalRateLimit);
  app.use(authenticate);

  // 7. Business endpoints (mounted at /api and /api/v1 for version compatibility)
  app.use('/api', apiRouter);
  app.use(API_PREFIX, apiRouter);

  // 8. Terminal middleware — both must be last, in this order.
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
