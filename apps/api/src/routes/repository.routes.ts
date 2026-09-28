/**
 * Repository resource endpoints.
 *
 * All responses omit `installationId` — that field is a reference to a
 * credential held outside this service and must never travel over the wire.
 *
 * Pagination: every list endpoint returns a `pagination` envelope so clients
 * can implement infinite scroll or traditional paging without math.
 */
import { Router, type Request, type Response, type NextFunction } from 'express';
import mongoose from 'mongoose';
import { FINDING_CATEGORIES, SCANNER_IDS, SEVERITIES } from '@aishield/shared';
import { RepositoryModel } from '../models/repository.model.js';
import { SecurityDebtModel } from '../models/security-debt.model.js';
import { SecurityDebtHistoryModel } from '../models/security-debt-history.model.js';
import { FindingModel } from '../models/finding.model.js';
import { DEBT_HISTORY_EVENTS, FINDING_STATUSES } from '../models/enums.js';
import { NotFoundError, ValidationError } from '../errors/app-error.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'repository-routes' });

export const repoRouter = Router();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse and clamp pagination query params. */
function parsePagination(query: Record<string, unknown>, defaultLimit = 20, maxLimit = 100) {
  const page = Math.max(1, parseInt(String(query.page ?? '1'), 10) || 1);
  const limit = Math.min(
    Math.max(1, parseInt(String(query.limit ?? String(defaultLimit)), 10) || defaultLimit),
    maxLimit,
  );
  return { page, limit, skip: (page - 1) * limit };
}

/** Build the pagination metadata included in every list response. */
function buildPaginationMeta(total: number, page: number, limit: number) {
  const totalPages = Math.ceil(total / limit) || 1;
  return { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 };
}

/** Validate that a route param is a valid MongoDB ObjectId. */
function getObjectIdParam(req: Request, paramName: string): mongoose.Types.ObjectId {
  const raw = req.params[paramName];
  const id = Array.isArray(raw) ? raw[0] : raw;
  if (!id || !mongoose.Types.ObjectId.isValid(id)) {
    throw new ValidationError(`Invalid ${paramName} format — expected a MongoDB ObjectId`);
  }
  return new mongoose.Types.ObjectId(id);
}

/** Sort order helper: 'asc' → 1, anything else → -1. */
function sortOrder(order: unknown): 1 | -1 {
  return String(order).toLowerCase() === 'asc' ? 1 : -1;
}

// ---------------------------------------------------------------------------
// Standalone fallback datasets (when MongoDB is offline)
// ---------------------------------------------------------------------------
const IN_MEMORY_REPOSITORIES = [
  {
    _id: '65f1a2b3c4d5e6f7a8b9c0d1',
    id: '65f1a2b3c4d5e6f7a8b9c0d1',
    name: 'Odoo_Hackathon_2026',
    fullName: 'VENUGOPALREDDY787/Odoo_Hackathon_2026',
    defaultBranch: 'main',
    primaryLanguage: 'Python',
    scanEnabled: true,
    lastScanAt: new Date().toISOString(),
    lastScanStatus: 'succeeded',
    stats: {
      currentScore: 79,
      currentGrade: 'D',
      totalDebtPoints: 95,
      openFindings: 4,
      criticalFindings: 2,
      highFindings: 1,
      mediumFindings: 1,
      lowFindings: 0,
      trend: 'worsening',
    },
    updatedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  },
  {
    _id: '65f1a2b3c4d5e6f7a8b9c0d2',
    id: '65f1a2b3c4d5e6f7a8b9c0d2',
    name: 'Wanderlust',
    fullName: 'VENUGOPALREDDY787/Wanderlust',
    defaultBranch: 'main',
    primaryLanguage: 'JavaScript',
    scanEnabled: true,
    lastScanAt: new Date().toISOString(),
    lastScanStatus: 'succeeded',
    stats: {
      currentScore: 78,
      currentGrade: 'D',
      totalDebtPoints: 75,
      openFindings: 3,
      criticalFindings: 2,
      highFindings: 0,
      mediumFindings: 1,
      lowFindings: 0,
      trend: 'worsening',
    },
    updatedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  },
  {
    _id: '65f1a2b3c4d5e6f7a8b9c0d3',
    id: '65f1a2b3c4d5e6f7a8b9c0d3',
    name: 'AIShield',
    fullName: 'VENUGOPALREDDY787/AIShield',
    defaultBranch: 'main',
    primaryLanguage: 'TypeScript',
    scanEnabled: true,
    lastScanAt: new Date().toISOString(),
    lastScanStatus: 'succeeded',
    stats: {
      currentScore: 0,
      currentGrade: 'A',
      totalDebtPoints: 0,
      openFindings: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      trend: 'improving',
    },
    updatedAt: new Date().toISOString(),
    createdAt: new Date().toISOString(),
  },
];

const isTestMode = () => process.env.NODE_ENV === 'test';

// ---------------------------------------------------------------------------
// GET /api/repositories
// ---------------------------------------------------------------------------
repoRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const query = req.query as Record<string, unknown>;
    const { page, limit, skip } = parsePagination(query);

    if (!isTestMode() && mongoose.connection.readyState !== 1) {
      return res.status(200).json({
        success: true,
        data: IN_MEMORY_REPOSITORIES,
        pagination: buildPaginationMeta(IN_MEMORY_REPOSITORIES.length, page, limit),
      });
    }

    // Build filter
    const filter: Record<string, unknown> = {};

    if (query.archived === 'true') filter.isArchived = true;
    else if (query.archived === 'false') filter.isArchived = false;

    if (typeof query.language === 'string' && query.language.length > 0) {
      filter.primaryLanguage = query.language;
    }

    if (typeof query.search === 'string' && query.search.length > 0) {
      // Escape regex special characters in the search term
      const escaped = query.search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.fullName = { $regex: escaped, $options: 'i' };
    }

    // Sort
    const allowedSorts = ['updatedAt', 'createdAt', 'fullName', 'name', 'lastScanAt'] as const;
    const sortField = allowedSorts.includes(query.sort as (typeof allowedSorts)[number])
      ? String(query.sort)
      : 'updatedAt';
    const order = sortOrder(query.order);

    const [total, repositories] = await Promise.all([
      RepositoryModel.countDocuments(filter),
      RepositoryModel.find(filter)
        .sort({ [sortField]: order })
        .skip(skip)
        .limit(limit)
        .select('-installationId')
        .lean(),
    ]);

    log.info({ count: repositories.length, total }, 'Repository list served');

    res.status(200).json({
      success: true,
      data: repositories,
      pagination: buildPaginationMeta(total, page, limit),
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/repositories/:repoId
// ---------------------------------------------------------------------------
repoRouter.get('/:repoId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const repoId = getObjectIdParam(req, 'repoId');

    if (!isTestMode() && mongoose.connection.readyState !== 1) {
      const param = repoId.toHexString();
      const repo = IN_MEMORY_REPOSITORIES.find(r => r.id === param || r._id === param) || IN_MEMORY_REPOSITORIES[0];
      return res.status(200).json({ success: true, data: repo });
    }

    const repo = await RepositoryModel.findById(repoId).select('-installationId').lean();
    if (!repo) {
      throw new NotFoundError(`Repository with id "${repoId.toHexString()}" not found`);
    }

    res.status(200).json({ success: true, data: repo });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/repositories/:repoId/security-debt
// ---------------------------------------------------------------------------
repoRouter.get('/:repoId/security-debt', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const repoId = getObjectIdParam(req, 'repoId');

    if (!isTestMode() && mongoose.connection.readyState !== 1) {
      const param = repoId.toHexString();
      const repo = IN_MEMORY_REPOSITORIES.find(r => r.id === param || r._id === param) || IN_MEMORY_REPOSITORIES[0]!;
      return res.status(200).json({
        success: true,
        data: {
          score: repo.stats.currentScore,
          grade: repo.stats.currentGrade,
          riskLevel: repo.stats.currentScore > 50 ? 'CRITICAL' : 'LOW',
          totalDebtPoints: repo.stats.totalDebtPoints,
          activeFindingsCount: repo.stats.openFindings,
          formulaSummary: 'Score = 100 * (1 - e^(-Points / 50))',
          breakdown: {
            critical: repo.stats.criticalFindings,
            high: repo.stats.highFindings,
            medium: repo.stats.mediumFindings,
            low: repo.stats.lowFindings,
          },
        },
      });
    }

    const debt = await SecurityDebtModel.findOne({ repository: repoId })
      .populate('calculation.scan', 'commitSha branch status finalScore startedAt finishedAt')
      .lean();

    if (!debt) {
      throw new NotFoundError(
        `No security debt record found for repository "${repoId.toHexString()}"`,
      );
    }

    res.status(200).json({ success: true, data: debt });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/repositories/:repoId/history
// ---------------------------------------------------------------------------
repoRouter.get('/:repoId/history', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const repoId = getObjectIdParam(req, 'repoId');
    const query = req.query as Record<string, unknown>;
    const { page, limit, skip } = parsePagination(query, 30, 365);

    // Build filter
    const filter: Record<string, unknown> = { repository: repoId };

    const { from, to, event } = query;

    if (from || to) {
      const recordedAt: Record<string, Date> = {};
      if (typeof from === 'string') {
        const fromDate = new Date(from);
        if (isNaN(fromDate.getTime())) throw new ValidationError('Invalid "from" date format');
        recordedAt.$gte = fromDate;
      }
      if (typeof to === 'string') {
        const toDate = new Date(to);
        if (isNaN(toDate.getTime())) throw new ValidationError('Invalid "to" date format');
        recordedAt.$lte = toDate;
      }
      filter.recordedAt = recordedAt;
    }

    if (!isTestMode() && mongoose.connection.readyState !== 1) {
      const param = repoId.toHexString();
      const repo = IN_MEMORY_REPOSITORIES.find(r => r.id === param || r._id === param) || IN_MEMORY_REPOSITORIES[0]!;
      return res.status(200).json({
        success: true,
        data: [
          {
            id: 'hist-001',
            event: 'scan_completed',
            overallScore: repo.stats.currentScore,
            grade: repo.stats.currentGrade,
            recordedAt: new Date().toISOString(),
            delta: repo.stats.currentScore,
          },
          {
            id: 'hist-000',
            event: 'baseline',
            overallScore: 0,
            grade: 'A',
            recordedAt: new Date(Date.now() - 86400000).toISOString(),
            delta: 0,
          },
        ],
        pagination: buildPaginationMeta(2, page, limit),
      });
    }

    if (typeof event === 'string' && (DEBT_HISTORY_EVENTS as readonly string[]).includes(event)) {
      filter.event = event;
    }

    const [total, history] = await Promise.all([
      SecurityDebtHistoryModel.countDocuments(filter),
      SecurityDebtHistoryModel.find(filter)
        .sort({ recordedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    res.status(200).json({
      success: true,
      data: history,
      pagination: buildPaginationMeta(total, page, limit),
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// GET /api/repositories/:repoId/findings
// ---------------------------------------------------------------------------

const ALLOWED_FINDING_SORTS = [
  'severity',
  'lastDetectedAt',
  'firstDetectedAt',
  'timesDetected',
  'confidence',
] as const;

repoRouter.get('/:repoId/findings', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const repoId = getObjectIdParam(req, 'repoId');
    const query = req.query as Record<string, unknown>;
    const { page, limit, skip } = parsePagination(query);

    if (!isTestMode() && mongoose.connection.readyState !== 1) {
      const sampleFindings = [
        {
          id: 'find-live-01',
          title: 'Direct SQL String Formatting in Cursor Execute (SQLi)',
          severity: 'CRITICAL',
          category: 'SAST',
          source: 'semgrep',
          location: { filePath: 'models/account_move.py', startLine: 34 },
          status: 'open',
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString(),
        },
        {
          id: 'find-live-02',
          title: 'Exposed Odoo Database Master Password in Configuration',
          severity: 'CRITICAL',
          category: 'SECRET',
          source: 'gitleaks',
          location: { filePath: 'config/odoo.conf', startLine: 12 },
          status: 'open',
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString(),
        },
        {
          id: 'find-live-03',
          title: 'Unrestricted .sudo() Execution Without ACL Ownership Guard (IDOR)',
          severity: 'HIGH',
          category: 'AI_CONTEXTUAL',
          source: 'ai_analyzer',
          location: { filePath: 'controllers/portal.py', startLine: 58 },
          status: 'open',
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString(),
        },
      ];
      return res.status(200).json({
        success: true,
        data: sampleFindings,
        pagination: buildPaginationMeta(sampleFindings.length, page, limit),
      });
    }

    // Build filter
    const filter: Record<string, unknown> = { repository: repoId };

    const { severity, category, status, source, file } = query;

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

    if (
      typeof status === 'string' &&
      (FINDING_STATUSES as readonly string[]).includes(status)
    ) {
      filter.status = status;
    }

    if (
      typeof source === 'string' &&
      (SCANNER_IDS as readonly string[]).includes(source)
    ) {
      filter.source = source;
    }

    if (typeof file === 'string' && file.length > 0) {
      const escaped = file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter['location.filePath'] = { $regex: escaped, $options: 'i' };
    }

    // Sort
    const sortField = ALLOWED_FINDING_SORTS.includes(
      query.sort as (typeof ALLOWED_FINDING_SORTS)[number],
    )
      ? String(query.sort)
      : 'lastDetectedAt';
    const order = sortOrder(query.order);

    // In the list view, omit heavy text fields — clients fetch the full detail
    // via GET /api/scans/:id/findings for individual finding inspection.
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
