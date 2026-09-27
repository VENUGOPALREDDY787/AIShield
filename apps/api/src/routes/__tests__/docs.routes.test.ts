/**
 * Tests for OpenAPI documentation endpoints.
 */
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../../app.js';

const app = createApp();

describe('OpenAPI Documentation Endpoints', () => {
  it('GET /api/openapi.json returns valid OpenAPI 3.1 schema', async () => {
    const response = await request(app).get('/api/openapi.json');
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('application/json');
    expect(response.body.openapi).toBe('3.1.0');
    expect(response.body.info.title).toBe('AIShield API');
    expect(response.body.paths).toHaveProperty('/api/repositories');
    expect(response.body.paths).toHaveProperty('/api/scans');
    expect(response.body.paths).toHaveProperty('/api/pull-requests/{id}');
  });

  it('GET /api/docs returns Swagger UI HTML', async () => {
    const response = await request(app).get('/api/docs');
    expect(response.status).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.text).toContain('SwaggerUIBundle');
    expect(response.text).toContain('AIShield API Documentation');
  });
});
