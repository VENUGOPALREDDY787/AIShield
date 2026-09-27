/**
 * API Documentation routes.
 *
 * Serves OpenAPI 3.1 JSON schema and interactive Swagger UI.
 */
import { Router } from 'express';
import { openApiSpec, renderSwaggerHtml } from '../docs/openapi.js';

export const docsRouter = Router();

docsRouter.get('/openapi.json', (_req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.status(200).json(openApiSpec);
});

docsRouter.get('/docs', (_req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(renderSwaggerHtml('/api/openapi.json'));
});
