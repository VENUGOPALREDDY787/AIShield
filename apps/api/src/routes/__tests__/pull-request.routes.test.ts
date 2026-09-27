/**
 * Tests for Pull Request endpoints.
 */
import request from 'supertest';
import { describe, expect, it, vi, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { createApp } from '../../app.js';
import { PullRequestModel } from '../../models/pull-request.model.js';
import { FindingModel } from '../../models/finding.model.js';

vi.mock('../../models/pull-request.model.js', () => ({
  PullRequestModel: {
    findById: vi.fn(),
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

describe('GET /api/pull-requests/:id', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns 422 for malformed ID', async () => {
    const response = await request(app).get('/api/pull-requests/invalid-pr-id');
    expect(response.status).toBe(422);
  });

  it('returns 404 when pull request does not exist', async () => {
    const mockQuery = {
      populate: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(null),
    };
    vi.mocked(PullRequestModel.findById).mockReturnValue(mockQuery as unknown as ReturnType<typeof PullRequestModel.findById>);

    const response = await request(app).get(`/api/pull-requests/${validMongoId}`);
    expect(response.status).toBe(404);
  });

  it('returns pull request with populated latestScan', async () => {
    const mockPR = {
      _id: validMongoId,
      number: 42,
      title: 'feat: add user authentication',
      state: 'open',
      findingsIntroduced: 2,
      findingsResolved: 5,
      scoreDelta: 10.0,
      latestScan: {
        status: 'succeeded',
        finalScore: { overall: 90.0, grade: 'A' },
      },
    };
    const mockQuery = {
      populate: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(mockPR),
    };
    vi.mocked(PullRequestModel.findById).mockReturnValue(mockQuery as unknown as ReturnType<typeof PullRequestModel.findById>);

    const response = await request(app).get(`/api/pull-requests/${validMongoId}`);
    expect(response.status).toBe(200);
    expect(response.body.data.title).toBe('feat: add user authentication');
    expect(response.body.data.scoreDelta).toBe(10.0);
  });
});

describe('GET /api/pull-requests/:id/findings', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns paginated findings for PR', async () => {
    const mockPR = {
      _id: validMongoId,
      repository: new mongoose.Types.ObjectId(),
      latestScan: new mongoose.Types.ObjectId(),
    };
    const mockPrQuery = {
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue(mockPR),
    };
    vi.mocked(PullRequestModel.findById).mockReturnValue(mockPrQuery as unknown as ReturnType<typeof PullRequestModel.findById>);

    vi.mocked(FindingModel.countDocuments).mockResolvedValue(1 as unknown as number);
    const mockFindingQuery = {
      sort: vi.fn().mockReturnThis(),
      skip: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      lean: vi.fn().mockResolvedValue([
        {
          _id: validMongoId,
          title: 'Hardcoded Secret in Auth Module',
          severity: 'CRITICAL',
          category: 'secrets',
        },
      ]),
    };
    vi.mocked(FindingModel.find).mockReturnValue(mockFindingQuery as unknown as ReturnType<typeof FindingModel.find>);

    const response = await request(app).get(
      `/api/pull-requests/${validMongoId}/findings?severity=CRITICAL`,
    );

    expect(response.status).toBe(200);
    expect(response.body.data).toHaveLength(1);
    expect(response.body.data[0].severity).toBe('CRITICAL');
  });
});
