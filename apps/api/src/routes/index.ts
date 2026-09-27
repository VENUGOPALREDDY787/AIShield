import { Router } from 'express';
import { scanRouter } from './scan.routes.js';
import { repoRouter } from './repository.routes.js';
import { prRouter } from './pull-request.routes.js';
import { docsRouter } from './docs.routes.js';

/**
 * Versioned API router.
 *
 * Feature routers are mounted here, one per resource. Keeping this file thin
 * means the URL surface of the API is readable in a single screen.
 */
export const apiRouter = Router();

apiRouter.use('/scans', scanRouter);
apiRouter.use('/repositories', repoRouter);
apiRouter.use('/pull-requests', prRouter);
apiRouter.use('/', docsRouter);
