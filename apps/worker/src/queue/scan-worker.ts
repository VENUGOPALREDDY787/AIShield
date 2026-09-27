/**
 * Security Analysis Worker — BullMQ consumer for the scan queue.
 *
 * Implements the asynchronous scanning pipeline:
 * 1. Update Scan document to 'running' + heartbeat
 * 2. Execute Scanners: Semgrep, Gitleaks, Dependency Scanner, AI Analyzer
 *    - Tolerates individual scanner failures without crashing the entire scan
 *    - Captures and stores individual component statuses
 * 3. Normalize and deduplicate findings via FindingNormalizerEngine
 * 4. Calculate Security Debt via SecurityDebtScoringEngine
 * 5. Persist findings, summary, and component statuses to MongoDB
 * 6. Report results to GitHub Check Run / PR Comment if in PR context
 */
import { Worker, type Job, type WorkerOptions } from 'bullmq';
import {
  SCAN_QUEUE_NAME,
  type NormalizedFinding,
  type ScannerId,
  type ScannerStatus,
  type ScanJobData,
  type ScanJobProgress,
  type ScanJobResult,
} from '@aishield/shared';
import { workerEnv } from '../config/env.js';
import { childLogger } from '../logging/logger.js';
import { FindingNormalizerEngine } from '../engine/finding-normalizer-engine.js';
import { SecurityDebtScoringEngine } from '../engine/debt-scoring-engine.js';
import {
  createDefaultOrchestrator,
  type ScannerOrchestrator,
} from '../scanners/index.js';
import { AIContextRunner } from '../runners/ai-runner.js';
import { getWorkerRedisClient } from './redis.js';
import { isMongoConnected } from '../db/mongo.js';
import { FindingModel, ScanModel, SecurityDebtModel } from '../db/models.js';
import { PRReporter } from '../github/pr-reporter.js';
import { GitHubClient } from '../github/github-client.js';
import { evaluateSecurityPolicy, loadPolicyConfig } from '../github/policy-engine.js';

const log = childLogger({ component: 'scan-worker' });

export interface ScanWorkerDependencies {
  orchestrator?: ScannerOrchestrator;
  normalizer?: FindingNormalizerEngine;
  debtEngine?: SecurityDebtScoringEngine;
  aiRunner?: AIContextRunner;
  githubClientFactory?: (token: string) => GitHubClient;
}

export interface CreateWorkerOptions {
  connection?: WorkerOptions['connection'];
  concurrency?: number;
  dependencies?: ScanWorkerDependencies;
}

export interface ComponentExecutionRecord {
  source: string;
  status: ScannerStatus;
  toolVersion?: string;
  startedAt: Date;
  finishedAt?: Date;
  durationMs: number;
  findingCount: number;
  error?: string;
}

/**
 * Executes the complete scan lifecycle for a single BullMQ job.
 */
export async function processScanJob(
  job: Job<ScanJobData, ScanJobResult>,
  deps: ScanWorkerDependencies = {},
): Promise<ScanJobResult> {
  const startedAt = Date.now();
  const {
    scanId,
    repositoryUrl,
    ref,
    commitSha = ref,
    baseSha,
    repoPath = workerEnv.SCANNER_WORK_DIR,
    scanners = ['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'],
    diffContent,
    githubToken,
    reportToGitHub,
    pullNumber,
    repositoryId,
    options = {},
  } = job.data;

  const jobId = job.id || `scan-${scanId}`;
  const jobLog = log.child({ jobId, scanId, repositoryUrl, ref, attempt: job.attemptsMade + 1 });

  jobLog.info('Starting security analysis job');

  // Initialize engines
  const orchestrator = deps.orchestrator || createDefaultOrchestrator();
  const normalizer = deps.normalizer || new FindingNormalizerEngine();
  const debtEngine = deps.debtEngine || new SecurityDebtScoringEngine();
  const aiRunner = deps.aiRunner || new AIContextRunner();

  // 1. Mark scan as 'running' in MongoDB + start heartbeat
  if (isMongoConnected()) {
    try {
      await ScanModel.findByIdAndUpdate(scanId, {
        status: 'running',
        jobId,
        startedAt: new Date(startedAt),
        heartbeatAt: new Date(startedAt),
        attempt: (job.attemptsMade ?? 0) + 1,
      });
    } catch (err) {
      jobLog.warn({ err }, 'Could not update scan status to running in MongoDB');
    }
  }

  // Periodic heartbeat timer
  const heartbeatTimer = setInterval(() => {
    if (isMongoConnected()) {
      ScanModel.findByIdAndUpdate(scanId, { heartbeatAt: new Date() }).catch(() => {});
    }
  }, 30_000);

  const componentStatuses: Record<string, ScannerStatus> = {};
  const componentRecords: ComponentExecutionRecord[] = [];
  const rawFindings: NormalizedFinding[] = [];
  let aiReport: Record<string, unknown> | undefined;

  const timeoutMs = options.timeoutMs || workerEnv.SCANNER_TIMEOUT_MS;

  const updateProgress = async (stage: string, scanner?: ScannerId, completed = 0, total = scanners.length) => {
    try {
      const progress: ScanJobProgress = {
        scanId,
        scanner,
        completed,
        total,
        stage,
        message: `Executing ${stage}`,
      };
      await job.updateProgress(progress);
    } catch {
      // Best-effort progress updates
    }
  };

  try {
    let completedSteps = 0;

    // --- Step 2a: Semgrep Static Security Scanner ---
    if (scanners.includes('semgrep')) {
      await updateProgress('semgrep', 'semgrep', completedSteps, scanners.length);
      const stepStart = Date.now();
      jobLog.info('Running Semgrep scanner');

      try {
        const semgrep = orchestrator.getScanner('semgrep');
        if (!semgrep) throw new Error('Semgrep scanner adapter not found in orchestrator');

        const res = await semgrep.scan({ targetPath: repoPath, timeoutMs });
        const duration = Date.now() - stepStart;
        const version = await semgrep.getVersion();

        componentStatuses.semgrep = 'succeeded';
        componentRecords.push({
          source: 'semgrep',
          status: 'succeeded',
          toolVersion: version,
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: res.findings.length,
        });

        rawFindings.push(...res.findings);
        jobLog.info({ findingCount: res.findings.length, durationMs: duration }, 'Semgrep scanner succeeded');
      } catch (err) {
        const duration = Date.now() - stepStart;
        const errorMsg = err instanceof Error ? err.message : String(err);
        componentStatuses.semgrep = 'failed';
        componentRecords.push({
          source: 'semgrep',
          status: 'failed',
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: 0,
          error: errorMsg,
        });
        jobLog.error({ err, errorMsg, durationMs: duration }, 'Semgrep scanner failed (pipeline continues)');
      }
      completedSteps++;
    }

    // --- Step 2b: Gitleaks Secrets Scanner ---
    if (scanners.includes('gitleaks')) {
      await updateProgress('gitleaks', 'gitleaks', completedSteps, scanners.length);
      const stepStart = Date.now();
      jobLog.info('Running Gitleaks secret scanner');

      try {
        const gitleaks = orchestrator.getScanner('gitleaks');
        if (!gitleaks) throw new Error('Gitleaks scanner adapter not found in orchestrator');

        const res = await gitleaks.scan({ targetPath: repoPath, timeoutMs });
        const duration = Date.now() - stepStart;
        const version = await gitleaks.getVersion();

        componentStatuses.gitleaks = 'succeeded';
        componentRecords.push({
          source: 'gitleaks',
          status: 'succeeded',
          toolVersion: version,
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: res.findings.length,
        });

        rawFindings.push(...res.findings);
        jobLog.info({ findingCount: res.findings.length, durationMs: duration }, 'Gitleaks scanner succeeded');
      } catch (err) {
        const duration = Date.now() - stepStart;
        const errorMsg = err instanceof Error ? err.message : String(err);
        componentStatuses.gitleaks = 'failed';
        componentRecords.push({
          source: 'gitleaks',
          status: 'failed',
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: 0,
          error: errorMsg,
        });
        jobLog.error({ err, errorMsg, durationMs: duration }, 'Gitleaks scanner failed (pipeline continues)');
      }
      completedSteps++;
    }

    // --- Step 2c: Dependency Vulnerability Scanner ---
    if (scanners.includes('dependency')) {
      await updateProgress('dependency', 'dependency', completedSteps, scanners.length);
      const stepStart = Date.now();
      jobLog.info('Running Dependency scanner');

      try {
        const dependency = orchestrator.getScanner('dependency');
        if (!dependency) throw new Error('Dependency scanner adapter not found in orchestrator');

        const res = await dependency.scan({ targetPath: repoPath, timeoutMs });
        const duration = Date.now() - stepStart;
        const version = await dependency.getVersion();

        componentStatuses.dependency = 'succeeded';
        componentRecords.push({
          source: 'dependency',
          status: 'succeeded',
          toolVersion: version,
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: res.findings.length,
        });

        rawFindings.push(...res.findings);
        jobLog.info({ findingCount: res.findings.length, durationMs: duration }, 'Dependency scanner succeeded');
      } catch (err) {
        const duration = Date.now() - stepStart;
        const errorMsg = err instanceof Error ? err.message : String(err);
        componentStatuses.dependency = 'failed';
        componentRecords.push({
          source: 'dependency',
          status: 'failed',
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: 0,
          error: errorMsg,
        });
        jobLog.error({ err, errorMsg, durationMs: duration }, 'Dependency scanner failed (pipeline continues)');
      }
      completedSteps++;
    }

    // --- Step 2d: AI Contextual Logic & Risk Analyzer ---
    if (scanners.includes('ai-analyzer')) {
      await updateProgress('ai-analyzer', 'ai-analyzer', completedSteps, scanners.length);
      const stepStart = Date.now();
      jobLog.info('Running AI Contextual Risk Analyzer');

      try {
        const res = await aiRunner.execute({
          scanId,
          repoPath,
          diffContent,
          deterministicFindings: rawFindings,
        });
        const duration = Date.now() - stepStart;

        if (res.status === 'succeeded') {
          componentStatuses['ai-analyzer'] = 'succeeded';
          rawFindings.push(...(res.findings as NormalizedFinding[]));
          aiReport = {
            provider: 'google-genai',
            durationMs: duration,
            findingsAnalyzed: rawFindings.length,
            suggestionsGenerated: res.findings.length,
          };
          componentRecords.push({
            source: 'ai-analyzer',
            status: 'succeeded',
            startedAt: new Date(stepStart),
            finishedAt: new Date(),
            durationMs: duration,
            findingCount: res.findings.length,
          });
          jobLog.info({ findingCount: res.findings.length, durationMs: duration }, 'AI Analyzer succeeded');
        } else {
          componentStatuses['ai-analyzer'] = 'failed';
          componentRecords.push({
            source: 'ai-analyzer',
            status: 'failed',
            startedAt: new Date(stepStart),
            finishedAt: new Date(),
            durationMs: duration,
            findingCount: 0,
            error: res.error,
          });
          jobLog.warn({ error: res.error }, 'AI Analyzer reported non-fatal error');
        }
      } catch (err) {
        const duration = Date.now() - stepStart;
        const errorMsg = err instanceof Error ? err.message : String(err);
        componentStatuses['ai-analyzer'] = 'failed';
        componentRecords.push({
          source: 'ai-analyzer',
          status: 'failed',
          startedAt: new Date(stepStart),
          finishedAt: new Date(),
          durationMs: duration,
          findingCount: 0,
          error: errorMsg,
        });
        jobLog.error({ err, errorMsg, durationMs: duration }, 'AI Analyzer failed (pipeline continues)');
      }
      completedSteps++;
    }

    // Assess overall scanner pipeline success:
    // A failed scanner should not fail the entire scan unless ALL requested scanners failed
    const requestedCount = scanners.length;
    const failedCount = Object.values(componentStatuses).filter((s) => s === 'failed').length;
    const allScannersFailed = requestedCount > 0 && failedCount === requestedCount;

    if (allScannersFailed) {
      jobLog.error({ componentStatuses }, 'All requested security scanners failed');
    }

    // --- Step 3: Normalization & Deduplication Engine ---
    await updateProgress('normalizer', undefined, completedSteps, scanners.length);
    jobLog.info('Normalizing and deduplicating findings');
    const normalizationResult = normalizer.processFindings({
      // Cast via unknown: NormalizedFinding satisfies all FindingInput fields but lacks
      // the [key: string]: unknown index signature — the normalizer only reads named fields.
      allFindings: rawFindings as unknown as Parameters<typeof normalizer.processFindings>[0]['allFindings'],
      scanId,
    });

    jobLog.info(
      {
        totalRaw: normalizationResult.totalRawFindings,
        unique: normalizationResult.uniqueFindingsCount,
        duplicatesRemoved: normalizationResult.duplicatesRemoved,
        correlated: normalizationResult.correlatedFindingsCount,
      },
      'Findings normalization complete',
    );

    // --- Step 4: Security Debt Scoring Engine ---
    await updateProgress('scoring', undefined, completedSteps, scanners.length);
    jobLog.info('Calculating Security Debt score');
    const debtResult = debtEngine.calculateDebt({
      findings: normalizationResult.unifiedFindings,
    });

    jobLog.info(
      {
        score: debtResult.score,
        riskLevel: debtResult.riskLevel,
        formula: debtResult.formulaSummary,
      },
      'Security Debt calculation complete',
    );

    const scanDurationMs = Date.now() - startedAt;
    const finalScanStatus = allScannersFailed ? 'failed' : 'succeeded';

    // --- Step 5: MongoDB Persistence ---
    await updateProgress('persistence', undefined, completedSteps, scanners.length);
    if (isMongoConnected()) {
      try {
        const savedFindingIds: unknown[] = [];

        // Save findings to MongoDB
        for (const finding of normalizationResult.unifiedFindings) {
          const doc = await FindingModel.findOneAndUpdate(
            { repository: repositoryId, fingerprint: finding.fingerprint },
            {
              $set: {
                repository: repositoryId,
                fingerprint: finding.fingerprint,
                scanner: finding.sources[0]?.source || 'unknown',
                category: finding.category,
                severity: finding.severity,
                title: finding.title,
                description: finding.description,
                location: {
                  filePath: finding.file,
                  startLine: finding.line,
                  endLine: finding.endLine,
                  snippet: finding.snippet,
                },
                cwe: finding.cwe,
                remediation: finding.remediation,
                confidence: finding.confidence,
                distinction: finding.distinction,
                metadata: finding.metadata,
                lastSeenScan: scanId,
                lastDetectedAt: new Date(),
              },
              $setOnInsert: {
                firstSeenScan: scanId,
                firstDetectedAt: new Date(),
              },
              $inc: { timesDetected: 1 },
            },
            { upsert: true, new: true },
          );
          if (doc) savedFindingIds.push((doc as { _id?: unknown })._id);
        }

        // Update Scan record
        await ScanModel.findByIdAndUpdate(scanId, {
          status: finalScanStatus,
          finishedAt: new Date(),
          durationMs: scanDurationMs,
          scannerResults: componentRecords,
          aiAnalysisStatus:
            componentStatuses['ai-analyzer'] === 'succeeded'
              ? 'completed'
              : componentStatuses['ai-analyzer'] === 'failed'
                ? 'failed'
                : 'not_requested',
          aiAnalysis: aiReport,
          finalScore: {
            overall: debtResult.score,
            previous: debtResult.previousScore,
            delta: debtResult.delta,
            grade: debtResult.riskLevel,
            calculatedAt: new Date(),
          },
          summary: {
            totalFindings: normalizationResult.uniqueFindingsCount,
            bySeverity: normalizationResult.bySeverity,
            byCategory: normalizationResult.byCategory,
          },
          findings: savedFindingIds,
          ...(allScannersFailed ? { error: { code: 'ALL_SCANNERS_FAILED', message: 'All requested scanners failed' } } : {}),
        });

        // Upsert latest SecurityDebt snapshot if repositoryId is known
        if (repositoryId) {
          await SecurityDebtModel.findOneAndUpdate(
            { repository: repositoryId },
            {
              repository: repositoryId,
              score: debtResult.score,
              riskLevel: debtResult.riskLevel,
              formulaSummary: debtResult.formulaSummary,
              severityBreakdown: debtResult.severityBreakdown,
              categoryBreakdown: debtResult.categoryBreakdown,
              topContributors: debtResult.topContributors,
              updatedAt: new Date(),
            },
            { upsert: true },
          );
        }

        jobLog.info('Persisted scan results and security debt to MongoDB');
      } catch (err) {
        jobLog.warn({ err }, 'Failed to persist scan results to MongoDB');
      }
    }

    // --- Step 6: GitHub Check Run & PR Comment (If requested in PR context) ---
    if ((reportToGitHub || pullNumber) && githubToken) {
      try {
        const clientFactory = deps.githubClientFactory || ((tok: string) => new GitHubClient({ token: tok }));
        const client = clientFactory(githubToken);

        const policyConfig = loadPolicyConfig({
          overrides: {
            ...(options.failOnCritical !== undefined || options.failOnHigh !== undefined
              ? {
                  maxAllowedNewFindings: {
                    maxCriticalAllowed: options.failOnCritical === false ? 999 : 0,
                    maxHighAllowed: options.failOnHigh ? 0 : 999,
                  },
                }
              : {}),
          },
        });

        const mockDeltaResult = {
          baseCommit: baseSha || 'unknown-base',
          headCommit: commitSha,
          baseScore: debtResult.previousScore ?? 0,
          headScore: debtResult.score,
          newDebt: debtResult.newDebt ?? 0,
          resolvedDebt: debtResult.resolvedDebt ?? 0,
          netDebtChange: debtResult.delta ?? 0,
          findingsIntroduced: normalizationResult.unifiedFindings.map((f) => ({
            finding: f,
            status: 'new' as const,
            isIntroducedByPR: true,
            reason: 'Observed in scan',
          })),
          findingsResolved: [],
          findingsModified: [],
          findingsUnchanged: [],
          totalHeadFindings: normalizationResult.uniqueFindingsCount,
          totalBaseFindings: 0,
          changedFilesCount: 1,
          summary: 'Automated Background Scan',
        };

        const policyResult = evaluateSecurityPolicy(mockDeltaResult, debtResult, policyConfig);

        const [owner, repoName] = (job.data.repositoryId || '').split('/');
        if (owner && repoName && pullNumber) {
          const reporter = new PRReporter(client);
          await reporter.reportPullRequest(mockDeltaResult, debtResult, {
            owner,
            repo: repoName,
            pullNumber,
            headSha: commitSha,
            dashboardUrl: job.data.dashboardUrl,
            policyResult,
          });
          jobLog.info({ policyStatus: policyResult.overallStatus }, 'Published PR security check to GitHub');
        }
      } catch (err) {
        jobLog.warn({ err }, 'Failed to publish PR security check to GitHub');
      }
    }

    clearInterval(heartbeatTimer);

    const result: ScanJobResult = {
      scanId,
      jobId,
      status: finalScanStatus,
      findingCount: normalizationResult.uniqueFindingsCount,
      durationMs: scanDurationMs,
      debtScore: debtResult.score,
      riskLevel: debtResult.riskLevel,
      componentStatuses,
      ...(allScannersFailed ? { error: 'All requested scanners failed' } : {}),
    };

    jobLog.info(
      {
        status: result.status,
        findingCount: result.findingCount,
        debtScore: result.debtScore,
        componentStatuses,
        durationMs: result.durationMs,
      },
      'Security analysis job finished',
    );

    return result;
  } catch (err) {
    clearInterval(heartbeatTimer);
    const durationMs = Date.now() - startedAt;
    const errorMsg = err instanceof Error ? err.message : String(err);

    jobLog.error({ err, errorMsg, durationMs }, 'Fatal error during scan job execution');

    if (isMongoConnected()) {
      try {
        await ScanModel.findByIdAndUpdate(scanId, {
          status: 'failed',
          finishedAt: new Date(),
          durationMs,
          error: { code: 'UNHANDLED_WORKER_ERROR', message: errorMsg },
        });
      } catch {
        // Ignore DB update error
      }
    }

    throw err;
  }
}

/**
 * Creates and registers the BullMQ Scan Worker.
 */
export function createScanWorker(options: CreateWorkerOptions = {}): Worker<ScanJobData, ScanJobResult> {
  const connection = options.connection || getWorkerRedisClient();
  const concurrency = options.concurrency ?? workerEnv.QUEUE_CONCURRENCY;

  log.info(
    {
      queue: SCAN_QUEUE_NAME,
      concurrency,
      prefix: workerEnv.QUEUE_PREFIX,
    },
    'Creating BullMQ Scan Worker',
  );

  const worker = new Worker<ScanJobData, ScanJobResult>(
    SCAN_QUEUE_NAME,
    async (job: Job<ScanJobData, ScanJobResult>) => {
      return processScanJob(job, options.dependencies);
    },
    {
      connection,
      prefix: workerEnv.QUEUE_PREFIX,
      concurrency,
      lockDuration: 60_000,
      stalledInterval: 30_000,
      maxStalledCount: 2,
    },
  );

  worker.on('active', (job) => {
    log.info({ jobId: job.id, scanId: job.data.scanId }, 'Worker picked up job');
  });

  worker.on('completed', (job, result) => {
    log.info(
      {
        jobId: job.id,
        scanId: job.data.scanId,
        status: result.status,
        findingCount: result.findingCount,
        durationMs: result.durationMs,
      },
      'Worker completed job',
    );
  });

  worker.on('failed', (job, err) => {
    log.error(
      {
        jobId: job?.id,
        scanId: job?.data.scanId,
        attempt: job?.attemptsMade,
        err,
      },
      'Worker job failed',
    );
  });

  worker.on('error', (err) => {
    log.error({ err }, 'Worker internal error');
  });

  return worker;
}
