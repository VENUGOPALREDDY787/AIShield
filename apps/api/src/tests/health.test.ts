/**
 * Boot-level smoke tests.
 *
 * These assert the *wiring*, not business logic: that the app can be built,
 * that the correlation id is applied, and that unmatched and unimplemented
 * routes all surface through the one centralized error envelope. Readiness is
 * intentionally not exercised — it needs live MongoDB and Redis, which belongs
 * in an integration suite.
 */
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import { API_PREFIX, HEALTH_PREFIX } from '../config/constants.js';

const app = createApp();

describe('GET /health (liveness)', () => {
  it('answers from process memory with the service identity', async () => {
    const response = await request(app).get(`${HEALTH_PREFIX}/`);

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      status: 'ok',
      service: 'aishield-api',
      environment: 'test',
    });
    expect(typeof response.body.uptimeSeconds).toBe('number');
  });

  it('echoes the correlation id on the response', async () => {
    const response = await request(app).get(`${HEALTH_PREFIX}/`).set('x-request-id', 'trace-abc');

    expect(response.headers['x-request-id']).toBe('trace-abc');
  });

  it('mints a correlation id when the caller does not supply one', async () => {
    const response = await request(app).get(`${HEALTH_PREFIX}/`);

    expect(response.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });
});

describe('unmatched routes', () => {
  it('returns the standard error envelope', async () => {
    const response = await request(app).get(`${API_PREFIX}/does-not-exist`);

    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOT_FOUND');
    expect(response.body.error.requestId).toBe(response.headers['x-request-id']);
  });
});

describe('scan routes (implemented endpoints)', () => {
  it('POST /scans returns 422 on missing required fields', async () => {
    // Missing commitSha and branch — should return validation error, not 501
    const response = await request(app)
      .post(`${API_PREFIX}/scans`)
      .send({ repositoryUrl: 'https://example.com/repo.git', ref: 'main' });

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('GET /scans/:scanId/report returns 422 for a non-ObjectId scan ID', async () => {
    // 'abc123' is not a valid MongoDB ObjectId — returns validation error
    const response = await request(app).get(`${API_PREFIX}/scans/abc123/report`);

    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });
});
