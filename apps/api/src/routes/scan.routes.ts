/**
 * Scan management endpoints.
 *
 * Enqueues scan jobs for background execution via BullMQ and Redis,
 * checks for duplicates, and provides scan status / reports.
 */
import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import mongoose from 'mongoose';
import {
  FINDING_CATEGORIES,
  isValidGitRef,
  SCANNER_IDS,
  SEVERITIES,
  validateRepositoryUrl,
  type ScannerId,
} from '@aishield/shared';
import { ScanModel, type Scan } from '../models/scan.model.js';
import { FindingModel } from '../models/finding.model.js';
import { FINDING_STATUSES } from '../models/enums.js';
import { getScanQueue } from '../queue/scan-queue.js';
import { ConflictError, NotFoundError, ValidationError } from '../errors/app-error.js';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'scan-routes' });

export const scanRouter = Router();

const createScanSchema = z.object({
  repository: z.string().min(1, 'repository ID or identifier is required'),
  commitSha: z.string().regex(/^[0-9a-f]{40}$/i, 'commitSha must be a 40-character git commit SHA'),
  branch: z.string().min(1, 'branch is required').refine(isValidGitRef, 'Invalid branch/ref name'),
  baseSha: z.string().regex(/^[0-9a-f]{40}$/i).optional(),
  baseBranch: z
    .string()
    .refine((val) => !val || isValidGitRef(val), 'Invalid base branch/ref name')
    .optional(),
  pullRequest: z.string().optional(),
  pullNumber: z.number().int().positive().optional(),
  repositoryUrl: z
    .string()
    .refine((url) => !url || validateRepositoryUrl(url).valid, {
      message: 'Invalid or forbidden repository URL (private network and cloud metadata URLs are blocked)',
    })
    .optional(),
  trigger: z.enum(['manual', 'pull_request', 'push', 'schedule']).default('manual'),
  scanners: z
    .array(z.enum([...SCANNER_IDS]))
    .min(1)
    .default(['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'] as unknown as [ScannerId, ...ScannerId[]]),
  options: z
    .object({
      timeoutMs: z.number().int().min(1000).optional(),
      diffOnly: z.boolean().optional(),
      labels: z.record(z.string(), z.string()).optional(),
      force: z.boolean().optional(),
      failOnCritical: z.boolean().optional(),
      failOnHigh: z.boolean().optional(),
    })
    .optional(),
});

function getScanIdParam(req: Request): string {
  const raw = req.params.scanId;
  const scanId = Array.isArray(raw) ? raw[0] : raw;
  if (!scanId || !mongoose.Types.ObjectId.isValid(scanId)) {
    throw new ValidationError('Invalid scan ID format');
  }
  return scanId;
}

/**
 * POST /api/scans
 * Enqueues a new security scan job into Redis via BullMQ.
 * Enforces duplicate scan prevention (idempotency).
 */
scanRouter.post('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const parseResult = createScanSchema.safeParse(req.body);
    if (!parseResult.success) {
      throw new ValidationError('Invalid scan request payload', {
        details: parseResult.error.flatten(),
      });
    }

    const payload = parseResult.data;
    const repoIdentifier = payload.repository;
    const isObjectId = mongoose.Types.ObjectId.isValid(repoIdentifier);
    const repoId = isObjectId ? new mongoose.Types.ObjectId(repoIdentifier) : repoIdentifier;

    // Idempotency & Duplicate Scan Prevention:
    // Check if an active (queued or running) scan already exists for this repo and commit
    const activeScan = await ScanModel.findOne<Scan>({
      repository: repoId,
      commitSha: payload.commitSha,
      status: { $in: ['queued', 'running'] },
    }).lean();

    if (activeScan && !payload.options?.force) {
      log.info(
        {
          existingScanId: activeScan._id,
          commitSha: payload.commitSha,
          status: activeScan.status,
        },
        'Duplicate scan rejected: active scan already in progress',
      );

      throw new ConflictError('An active scan is already queued or running for this commit', {
        details: {
          existingScanId: activeScan._id,
          status: activeScan.status,
          enqueuedAt: activeScan.enqueuedAt,
        },
      });
    }

    // Create the Scan document in MongoDB
    const scanDoc = await ScanModel.create({
      repository: isObjectId ? repoId : new mongoose.Types.ObjectId(),
      commitSha: payload.commitSha,
      branch: payload.branch,
      baseSha: payload.baseSha,
      baseBranch: payload.baseBranch,
      pullRequest: payload.pullRequest && mongoose.Types.ObjectId.isValid(payload.pullRequest)
        ? new mongoose.Types.ObjectId(payload.pullRequest)
        : undefined,
      trigger: payload.trigger,
      status: 'queued',
      enqueuedAt: new Date(),
    });

    const scanId = scanDoc._id.toString();
    const jobId = `scan-${scanId}`;

    // Add job to BullMQ queue
    const queue = getScanQueue();
    const job = await queue.add(
      'scan-analysis',
      {
        scanId,
        repositoryUrl: payload.repositoryUrl || `https://github.com/repo/${repoIdentifier}`,
        ref: payload.commitSha,
        commitSha: payload.commitSha,
        baseSha: payload.baseSha,
        branch: payload.branch,
        pullNumber: payload.pullNumber,
        repositoryId: repoIdentifier,
        scanners: payload.scanners,
        requestedAt: new Date().toISOString(),
        options: payload.options,
      },
      {
        jobId,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 5_000,
        },
        removeOnComplete: true,
        removeOnFail: false,
      },
    );

    log.info(
      { scanId, jobId: job.id, commitSha: payload.commitSha, scanners: payload.scanners },
      'Scan job successfully created and enqueued',
    );

    res.status(201).json({
      success: true,
      data: {
        scanId,
        jobId: job.id,
        status: 'queued',
        enqueuedAt: scanDoc.enqueuedAt,
        commitSha: scanDoc.commitSha,
        branch: scanDoc.branch,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/scans/:scanId
 * Retrieves current scan status, individual component statuses, score, and summary.
 */
scanRouter.get('/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const scanId = getScanIdParam(req);

    const scan = await ScanModel.findById(scanId).lean();
    if (!scan) {
      throw new NotFoundError(`Scan with id "${scanId}" not found`);
    }

    res.status(200).json({
      success: true,
      data: scan,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/scans/:scanId/report
 * Retrieves full scan report including observed findings.
 */
scanRouter.get('/:scanId/report', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const scanId = getScanIdParam(req);

    const scan = await ScanModel.findById<Scan>(scanId).populate('findings').lean();
    if (!scan) {
      throw new NotFoundError(`Scan with id "${scanId}" not found`);
    }

    res.status(200).json({
      success: true,
      data: {
        scanId: scan._id,
        status: scan.status,
        finalScore: scan.finalScore,
        summary: scan.summary,
        scannerResults: scan.scannerResults,
        aiAnalysisStatus: scan.aiAnalysisStatus,
        findings: scan.findings,
        startedAt: scan.startedAt,
        finishedAt: scan.finishedAt,
        durationMs: scan.durationMs,
      },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/scans
 * Lists recent scans with optional filtering.
 */
scanRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { repository, status, limit = '20' } = req.query;
    const filter: Record<string, unknown> = {};

    if (repository && typeof repository === 'string' && mongoose.Types.ObjectId.isValid(repository)) {
      filter.repository = new mongoose.Types.ObjectId(repository);
    }
    if (status && typeof status === 'string') {
      filter.status = status;
    }

    const maxResults = Math.min(Math.max(parseInt(String(limit), 10) || 20, 1), 100);
    const scans = await ScanModel.find(filter)
      .sort({ createdAt: -1 })
      .limit(maxResults)
      .lean();

    res.status(200).json({
      success: true,
      data: scans,
      count: scans.length,
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/scans/:scanId/findings
 * Lists findings observed in this specific scan with filtering and pagination.
 */
const SCAN_FINDING_SORTS = ['severity', 'lastDetectedAt', 'firstDetectedAt', 'timesDetected'] as const;

scanRouter.get('/:scanId/findings', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const scanId = getScanIdParam(req);
    const query = req.query as Record<string, unknown>;

    // Parse pagination
    const page = Math.max(1, parseInt(String(query.page ?? '1'), 10) || 1);
    const limit = Math.min(Math.max(1, parseInt(String(query.limit ?? '20'), 10) || 20), 100);
    const skip = (page - 1) * limit;

    // Verify the scan exists
    const scanExists = await ScanModel.exists({ _id: scanId });
    if (!scanExists) {
      throw new NotFoundError(`Scan with id "${scanId}" not found`);
    }

    // Findings observed in this scan (via lastSeenScan or firstSeenScan)
    const filter: Record<string, unknown> = {
      $or: [{ firstSeenScan: scanId }, { lastSeenScan: scanId }],
    };

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

    const sortField = SCAN_FINDING_SORTS.includes(query.sort as (typeof SCAN_FINDING_SORTS)[number])
      ? String(query.sort)
      : 'lastDetectedAt';
    const order: 1 | -1 = String(query.order).toLowerCase() === 'asc' ? 1 : -1;

    const [total, findings] = await Promise.all([
      FindingModel.countDocuments(filter),
      FindingModel.find(filter)
        .sort({ [sortField]: order })
        .skip(skip)
        .limit(limit)
        .lean(),
    ]);

    const totalPages = Math.ceil(total / limit) || 1;
    res.status(200).json({
      success: true,
      data: findings,
      pagination: { page, limit, total, totalPages, hasNext: page < totalPages, hasPrev: page > 1 },
    });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/scans/:scanId
 * Cancels a queued or running scan.
 */
scanRouter.delete('/:scanId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const scanId = getScanIdParam(req);

    const scan = await ScanModel.findById(scanId);
    if (!scan) {
      throw new NotFoundError(`Scan with id "${scanId}" not found`);
    }

    if (scan.status === 'succeeded' || scan.status === 'failed' || scan.status === 'cancelled') {
      res.status(200).json({
        success: true,
        message: `Scan is already in terminal state "${scan.status}"`,
        data: scan,
      });
      return;
    }

    scan.status = 'cancelled';
    scan.finishedAt = new Date();
    await scan.save();

    // Try to remove job from BullMQ queue if still queued
    try {
      const queue = getScanQueue();
      const job = await queue.getJob(`scan-${scanId}`);
      if (job) {
        await job.remove();
      }
    } catch {
      // Best-effort job removal
    }

    log.info({ scanId }, 'Scan successfully cancelled');

    res.status(200).json({
      success: true,
      data: {
        scanId,
        status: 'cancelled',
      },
    });
  } catch (err) {
    next(err);
  }
});
