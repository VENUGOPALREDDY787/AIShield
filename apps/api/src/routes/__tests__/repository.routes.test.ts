/**
 * Tests for Repository endpoints.
 *
 * Tests validation, pagination, sorting, filtering, and 404s.
 */
import request from 'supertest';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { createApp } from '../../app.js';
import { RepositoryModel } from '../../models/repository.model.js';
import { SecurityDebtModel } from '../../models/security-debt.model.js';
import { SecurityDebtHistoryModel } from '../../models/security-debt-history.model.js';
import { FindingModel } from '../../models/finding.model.js';

vi.mock('../../models/repository.model.js', () => ({
  RepositoryModel: {
    countDocuments: vi.fn(),
    find: vi.fn(),
    findById: vi.fn(),
  },
}));

vi.mock('../../models/security-debt.model.js', () => ({
  SecurityDebtModel: {
    findOne: vi.fn(),
  },
}));

vi.mock('../../models/security-debt-history.model.js', () => ({
  SecurityDebtHistoryModel: {
    countDocuments: vi.fn(),
    find: vi.fn(),
  },
}));

vi.mock('../../models/finding.model.js', () => ({
  FindingModel: {
    countDocuments: vi.fn(),
    find: vi.fn(),
  },
}));

const app = createApp();
const validMongoId = new mongoose.Types.ObjectId().toHexString();

describe('GET /api/repositories', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns paginated repositories list', async () => {
    const mockRepos = [
      {
        _id: validMongoId,
        fullName: 'owner/repo-1',
        name: 'repo-1',
        primaryLanguage: 'TypeScript',
        stats: { openFindings: 3, criticalFindings: 0 },
      },
    ];

    vi.mocked(RepositoryModel.countDocuments).mockResolvedValue(1 as unknown as number);
    const mockQuery = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(mockRepos),
    };
    vi.mocked(RepositoryModel.find).mockReturnValue(mockQuery as unknown as ReturnType<typeof RepositoryModel.find>);

    const response = await request(app).get('/api/repositories?page=1&limit=10');

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.data).toHaveLength(1);
    expect(response.body.pagination).toEqual({
      page: 1,
      limit: 10,
      total: 1,
      totalPages: 1,
      hasNext: false,
      hasPrev: false,
    });
  });

  it('filters by language, archived status, and search string', async () => {
    vi.mocked(RepositoryModel.countDocuments).mockResolvedValue(0 as unknown as number);
    const mockQuery = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([]),
    };
    vi.mocked(RepositoryModel.find).mockReturnValue(mockQuery as unknown as ReturnType<typeof RepositoryModel.find>);

    const response = await request(app).get(
      '/api/repositories?language=Go&archived=false&search=my-service',
    );

    expect(response.status).toBe(200);
    expect(RepositoryModel.countDocuments).toHaveBeenCalledWith(
      expect.objectContaining({
        primaryLanguage: 'Go',
        isArchived: false,
        fullName: expect.objectContaining({ $regex: 'my-service' }),
      }),
    );
  });
});

describe('GET /api/repositories/:id', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 422 for invalid MongoDB ObjectId', async () => {
    const response = await request(app).get('/api/repositories/invalid-id');
    expect(response.status).toBe(422);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('returns 404 when repository does not exist', async () => {
    const mockQuery = {
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(null),
    };
    vi.mocked(RepositoryModel.findById).mockReturnValue(mockQuery as unknown as ReturnType<typeof RepositoryModel.findById>);

    const response = await request(app).get(`/api/repositories/${validMongoId}`);
    expect(response.status).toBe(404);
    expect(response.body.error.code).toBe('NOT_FOUND');
  });

  it('returns repository details when found', async () => {
    const mockRepo = {
      _id: validMongoId,
      fullName: 'org/security-service',
      defaultBranch: 'main',
    };
    const mockQuery = {
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(mockRepo),
    };
    vi.mocked(RepositoryModel.findById).mockReturnValue(mockQuery as unknown as ReturnType<typeof RepositoryModel.findById>);

    const response = await request(app).get(`/api/repositories/${validMongoId}`);
    expect(response.status).toBe(200);
    expect(response.body.data.fullName).toBe('org/security-service');
  });
});

describe('GET /api/repositories/:id/security-debt', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 404 when no debt record exists', async () => {
    const mockQuery = {
      populate: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(null),
    };
    vi.mocked(SecurityDebtModel.findOne).mockReturnValue(mockQuery as unknown as ReturnType<typeof SecurityDebtModel.findOne>);

    const response = await request(app).get(`/api/repositories/${validMongoId}/security-debt`);
    expect(response.status).toBe(404);
  });

  it('returns security debt snapshot when found', async () => {
    const mockDebt = {
      overallScore: 85.5,
      previousScore: 80.0,
      delta: 5.5,
      grade: 'B',
      trend: 'improving',
      severityBreakdown: { CRITICAL: 0, HIGH: 1, MEDIUM: 3, LOW: 5, INFO: 8 },
    };
    const mockQuery = {
      populate: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(mockDebt),
    };
    vi.mocked(SecurityDebtModel.findOne).mockReturnValue(mockQuery as unknown as ReturnType<typeof SecurityDebtModel.findOne>);

    const response = await request(app).get(`/api/repositories/${validMongoId}/security-debt`);
    expect(response.status).toBe(200);
    expect(response.body.data.overallScore).toBe(85.5);
    expect(response.body.data.grade).toBe('B');
  });
});

describe('GET /api/repositories/:id/history', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns paginated debt history with date range filtering', async () => {
    vi.mocked(SecurityDebtHistoryModel.countDocuments).mockResolvedValue(2 as unknown as number);
    const mockQuery = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        { event: 'scan_completed', overallScore: 85.0, recordedAt: new Date().toISOString() },
        { event: 'baseline', overallScore: 75.0, recordedAt: new Date().toISOString() },
      ]),
    };
    vi.mocked(SecurityDebtHistoryModel.find).mockReturnValue(mockQuery as unknown as ReturnType<typeof SecurityDebtHistoryModel.find>);

    const response = await request(app).get(
      `/api/repositories/${validMongoId}/history?from=2026-01-01T00:00:00Z&to=2026-12-31T23:59:59Z&event=scan_completed`,
    );

    expect(response.status).toBe(200);
    expect(response.body.data).toHaveLength(2);
    expect(response.body.pagination.total).toBe(2);
  });

  it('returns 422 for invalid date strings', async () => {
    const response = await request(app).get(
      `/api/repositories/${validMongoId}/history?from=not-a-valid-date`,
    );
    expect(response.status).toBe(422);
  });
});

describe('GET /api/repositories/:id/findings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns paginated findings with severity and category filter', async () => {
    vi.mocked(FindingModel.countDocuments).mockResolvedValue(1 as unknown as number);
    const mockQuery = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        {
          _id: validMongoId,
          title: 'SQL Injection in Query Builder',
          severity: 'HIGH',
          category: 'injection',
          status: 'open',
        },
      ]),
    };
    vi.mocked(FindingModel.find).mockReturnValue(mockQuery as unknown as ReturnType<typeof FindingModel.find>);

    const response = await request(app).get(
      `/api/repositories/${validMongoId}/findings?severity=HIGH&category=injection&sort=severity&order=desc`,
    );

    expect(response.status).toBe(200);
    expect(response.body.data[0].title).toBe('SQL Injection in Query Builder');
    expect(mockQuery.select).toHaveBeenCalledWith('-location.snippet -description');
  });
});
