/**
 * Pull-request resource endpoints.
 *
 * Pull requests are created/updated by the GitHub Action integration and
 * read by the dashboard. This router exposes the read side only — writes
 * happen through the scanner pipeline.
 */
import { Router, type Request, type Response, type NextFunction } from 'express';
import mongoose from 'mongoose';
import { PullRequestModel } from '../models/pull-request.model.js';
import { FindingModel } from '../models/finding.model.js';
import { FINDING_CATEGORIES, SCANNER_IDS, SEVERITIES } from '@aishield/shared';
import { FINDING_STATUSES } from '../models/enums.js';
import { NotFoundError, ValidationError } from '../errors/app-error.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'pull-request-routes' });

export const prRouter = Router();

/** Validate and parse a MongoDB ObjectId from request params. */
function getObjectIdParam(req: Request, paramName: string): mongoose.Types.ObjectId {
  const raw = req.params[paramName];
  const id = Array.isArray(raw) ? raw[0] : raw;
  if (id === undefined || id === null || !mongoose.Types.ObjectId.isValid(id)) {
    throw new ValidationError(`Invalid ${paramName} format — expected a MongoDB ObjectId`);
  }
  return new mongoose.Types.ObjectId(id);
}

function parsePagination(query: Record<string, unknown>, defaultLimit = 20, maxLimit = 100) {
  const page = Math.max(1, parseInt(String(query.page ?? '1'), 10) || 1);
  const limit = Math.min(
    Math.max(1, parseInt(String(query.limit ?? String(defaultLimit)), 10) || defaultLimit),
    maxLimit,
  );
  return { page, limit, skip: (page - 1) * limit };
}

function buildPaginationMeta(total: number, page: number, limit: number) {
  const totalPages = Math.ceil(total / limit) || 1;
  return { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 };
}

function sortOrder(order: unknown): 1 | -1 {
  return String(order).toLowerCase() === 'asc' ? 1 : -1;
}

// ---------------------------------------------------------------------------
// GET /api/pull-requests/:prId
// ---------------------------------------------------------------------------
prRouter.get('/:prId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prId = getObjectIdParam(req, 'prId');

    const pr = await PullRequestModel.findById(prId)
      .populate('latestScan', 'status commitSha finalScore summary startedAt finishedAt durationMs')
      .lean();

    if (!pr) {
      throw new NotFoundError(`Pull request with id "${prId.toHexString()}" not found`);
    }

    log.info({ prId: prId.toHexString() }, 'Pull request served');

    res.status(200).json({ success: true, data: pr });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/pull-requests/:prId/findings
// Findings introduced or observed in the context of this PR's head commit.
// ---------------------------------------------------------------------------

const ALLOWED_SORTS = ['severity', 'lastDetectedAt', 'firstDetectedAt', 'timesDetected'] as const;

prRouter.get('/:prId/findings', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const prId = getObjectIdParam(req, 'prId');
    const query = req.query as Record<string, unknown>;

    // First fetch the PR to get the repository scope
    const pr = await PullRequestModel.findById(prId).select('repository latestScan').lean();
    if (!pr) {
      throw new NotFoundError(`Pull request with id "${prId.toHexString()}" not found`);
    }

    const { page, limit, skip } = parsePagination(query);

    // Findings scoped to the PR's repository, first seen in the PR's latest scan
    const filter: Record<string, unknown> = { repository: pr.repository };

    if (pr.latestScan) {
      filter.firstSeenScan = pr.latestScan;
    }

    const { severity, category, status, source } = query;

    if (
      typeof severity === 'string' &&
      (SEVERITIES as readonly string[]).includes(severity.toUpperCase())
    ) {
      filter.severity = severity.toUpperCase();
    }

    if (
      typeof category === 'string' &&
      (FINDING_CATEGORIES as readonly string[]).includes(category)
    ) {
      filter.category = category;
    }

    if (typeof status === 'string' && (FINDING_STATUSES as readonly string[]).includes(status)) {
      filter.status = status;
    }

    if (typeof source === 'string' && (SCANNER_IDS as readonly string[]).includes(source)) {
      filter.source = source;
    }

    const sortField = ALLOWED_SORTS.includes(query.sort as (typeof ALLOWED_SORTS)[number])
      ? String(query.sort)
      : 'lastDetectedAt';
    const order = sortOrder(query.order);

    const [total, findings] = await Promise.all([
      FindingModel.countDocuments(filter),
      FindingModel.find(filter)
        .sort({ [sortField]: order })
        .skip(skip)
        .limit(limit)
        .select('-location.snippet -description')
        .lean(),
    ]);

    res.status(200).json({
      success: true,
      data: findings,
      pagination: buildPaginationMeta(total, page, limit),
    });
  } catch (err) {
    next(err);
  }
});
