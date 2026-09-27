import { describe, expect, it, vi } from 'vitest';
import type { Request, Response } from 'express';
import { authenticate } from '../auth.js';

describe('authenticate middleware', () => {
  it('allows health endpoints without checking API key', () => {
    const req = { path: '/health', headers: {} } as unknown as Request;
    const res = {} as Response;
    const next = vi.fn();

    authenticate(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('allows docs endpoints without API key', () => {
    const req = { path: '/api/openapi.json', headers: {} } as unknown as Request;
    const res = {} as Response;
    const next = vi.fn();

    authenticate(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('sets dev-bypass auth context under test/dev mode when no key is set', () => {
    const req = { path: '/api/repositories', headers: {} } as unknown as Request;
    const res = {} as Response;
    const next = vi.fn();

    authenticate(req, res, next);
    expect(next).toHaveBeenCalledWith();
    expect(req.auth).toEqual({
      userId: 'dev-user',
      role: 'admin',
      method: 'dev-bypass',
    });
  });
});
