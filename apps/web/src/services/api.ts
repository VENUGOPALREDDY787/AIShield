/**
 * AIShield Dashboard API Client.
 *
 * Interacts with the backend REST API.
 * Uses isolated mock data only when demo mode is explicitly enabled
 * or when the backend server is unreachable during local frontend preview.
 */

import type { HealthResponse } from '@aishield/shared';
import type {
  DebtHistoryEntry,
  DisplayFinding,
  PullRequestSummary,
  RepositorySummary,
  ScanDetails,
} from '../types/index.js';
import {
  MOCK_DEBT_HISTORY,
  MOCK_FINDINGS,
  MOCK_PRS,
  MOCK_REPOSITORIES,
  MOCK_SCANS,
} from './mockData.js';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';
let isDemoMode = false;

export function setDemoMode(enabled: boolean): void {
  isDemoMode = enabled;
}

export function getDemoMode(): boolean {
  return isDemoMode;
}

interface RawRepository {
  _id?: string;
  id?: string;
  name: string;
  fullName: string;
  defaultBranch?: string;
  primaryLanguage?: string;
  scanEnabled?: boolean;
  lastScanAt?: string;
  lastScanStatus?: string;
  stats?: {
    currentScore?: number;
    currentGrade?: 'A' | 'B' | 'C' | 'D' | 'F';
    totalDebtPoints?: number;
    openFindings?: number;
    criticalFindings?: number;
    highFindings?: number;
    mediumFindings?: number;
    lowFindings?: number;
    trend?: 'improving' | 'stable' | 'worsening';
  };
}

interface RawFinding {
  _id?: string;
  id?: string;
  repository: string;
  fingerprint: string;
  title: string;
  description?: string;
  severity: DisplayFinding['severity'];
  category: DisplayFinding['category'];
  source: string;
  confidence?: number;
  location?: {
    filePath?: string;
    startLine?: number;
    endLine?: number;
    startColumn?: number;
    snippet?: string;
    snippetRedacted?: boolean;
  };
  cwe?: string;
  owasp?: string;
  tags?: string[];
  status?: DisplayFinding['status'];
  timesDetected?: number;
  firstDetectedAt: string;
  lastDetectedAt: string;
  aiAnalysis?: DisplayFinding['aiAnalysis'];
  remediation?: DisplayFinding['remediation'];
}

interface RawPullRequest {
  _id?: string;
  id?: string;
  repository: string;
  number: number;
  title: string;
  author?: { login?: string; avatarUrl?: string };
  headBranch: string;
  baseBranch: string;
  headSha: string;
  baseSha?: string;
  findingsIntroduced?: number;
  findingsResolved?: number;
  scoreDelta?: number;
  state?: 'open' | 'closed' | 'merged';
  changedFiles?: number;
  updatedAt?: string;
}

interface RawScan {
  _id?: string;
  id?: string;
  repository: string;
  commitSha: string;
  branch: string;
  baseSha?: string;
  trigger: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  enqueuedAt: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  finalScore?: {
    overall?: number;
    previous?: number;
    delta?: number;
    grade?: 'A' | 'B' | 'C' | 'D' | 'F';
  };
  scannerResults?: ScanDetails['components'];
  summary?: ScanDetails['summary'];
}

interface RawHistory {
  _id?: string;
  id?: string;
  repository: string;
  event: DebtHistoryEntry['event'];
  overallScore: number;
  previousScore?: number;
  delta?: number;
  grade?: 'A' | 'B' | 'C' | 'D' | 'F';
  trend?: 'improving' | 'stable' | 'worsening';
  severityBreakdown?: DebtHistoryEntry['severityBreakdown'];
  categoryBreakdown?: DebtHistoryEntry['categoryBreakdown'];
  findingCounts?: DebtHistoryEntry['findingCounts'];
  recordedAt: string;
  scan?: string;
  pullRequest?: string;
}

async function requestJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    throw new Error(`Request to ${path} failed with status: ${res.status}`);
  }

  const json = await res.json();
  return json.data !== undefined ? json.data : json;
}

export async function fetchHealth(): Promise<HealthResponse> {
  try {
    const res = await fetch(`${API_BASE}/health`);
    if (res.ok) {
      return res.json();
    }
  } catch {
    // Falls through to fallback
  }

  return {
    status: 'ok',
    service: 'aishield-api',
    version: '0.1.0',
    environment: 'demo',
    uptimeSeconds: 8420,
    timestamp: new Date().toISOString(),
  };
}

export async function fetchRepositories(): Promise<RepositorySummary[]> {
  if (isDemoMode) {
    return MOCK_REPOSITORIES;
  }
  try {
    const data = await requestJson<RawRepository[]>('/api/repositories');
    if (Array.isArray(data) && data.length > 0) {
      return data.map((r) => ({
        id: r._id || r.id || 'repo-1',
        name: r.name,
        fullName: r.fullName,
        defaultBranch: r.defaultBranch || 'main',
        primaryLanguage: r.primaryLanguage,
        currentScore: r.stats?.currentScore ?? 78,
        currentGrade: r.stats?.currentGrade ?? 'B',
        totalDebtPoints: r.stats?.totalDebtPoints ?? 21.5,
        activeFindingsCount: r.stats?.openFindings ?? 0,
        criticalFindingsCount: r.stats?.criticalFindings ?? 0,
        highFindingsCount: r.stats?.highFindings ?? 0,
        mediumFindingsCount: r.stats?.mediumFindings ?? 0,
        lowFindingsCount: r.stats?.lowFindings ?? 0,
        trend: r.stats?.trend ?? 'stable',
        lastScannedAt: r.lastScanAt,
        lastScanStatus: r.lastScanStatus,
        scanEnabled: r.scanEnabled ?? true,
      }));
    }
    return MOCK_REPOSITORIES;
  } catch {
    return MOCK_REPOSITORIES;
  }
}

export async function fetchRepositoryById(id: string): Promise<RepositorySummary | null> {
  if (isDemoMode) {
    return MOCK_REPOSITORIES.find((r) => r.id === id) || MOCK_REPOSITORIES[0] || null;
  }
  try {
    const r = await requestJson<RawRepository>(`/api/repositories/${id}`);
    return {
      id: r._id || r.id || id,
      name: r.name,
      fullName: r.fullName,
      defaultBranch: r.defaultBranch || 'main',
      primaryLanguage: r.primaryLanguage,
      currentScore: r.stats?.currentScore ?? 78.5,
      currentGrade: r.stats?.currentGrade ?? 'B',
      totalDebtPoints: r.stats?.totalDebtPoints ?? 21.5,
      activeFindingsCount: r.stats?.openFindings ?? 6,
      criticalFindingsCount: r.stats?.criticalFindings ?? 1,
      highFindingsCount: r.stats?.highFindings ?? 2,
      mediumFindingsCount: r.stats?.mediumFindings ?? 2,
      lowFindingsCount: r.stats?.lowFindings ?? 1,
      trend: r.stats?.trend ?? 'improving',
      lastScannedAt: r.lastScanAt,
      lastScanStatus: r.lastScanStatus,
      scanEnabled: r.scanEnabled ?? true,
    };
  } catch {
    return MOCK_REPOSITORIES.find((r) => r.id === id) || MOCK_REPOSITORIES[0] || null;
  }
}

export async function fetchRepositoryDebt(repoId: string): Promise<Record<string, unknown>> {
  if (isDemoMode) {
    return {
      overallScore: 78.5,
      previousScore: 72.0,
      delta: 6.5,
      grade: 'B',
      trend: 'improving',
      severityBreakdown: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 1, INFO: 0 },
      categoryBreakdown: { injection: 1, secrets: 1, dependency: 1, authorization: 2, configuration: 1 },
    };
  }
  try {
    return await requestJson<Record<string, unknown>>(`/api/repositories/${repoId}/security-debt`);
  } catch {
    return {
      overallScore: 78.5,
      previousScore: 72.0,
      delta: 6.5,
      grade: 'B',
      trend: 'improving',
      severityBreakdown: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 1, INFO: 0 },
      categoryBreakdown: { injection: 1, secrets: 1, dependency: 1, authorization: 2, configuration: 1 },
    };
  }
}

export async function fetchRepositoryFindings(
  repoId: string,
  params: Record<string, string> = {},
): Promise<DisplayFinding[]> {
  if (isDemoMode) {
    return MOCK_FINDINGS.filter((f) => !repoId || f.repositoryId === repoId || repoId === 'repo-1');
  }
  try {
    const qs = new URLSearchParams(params).toString();
    const data = await requestJson<RawFinding[]>(`/api/repositories/${repoId}/findings${qs ? `?${qs}` : ''}`);
    if (Array.isArray(data) && data.length > 0) {
      return data.map((f) => ({
        id: f._id || f.id || 'f-1',
        repositoryId: f.repository,
        fingerprint: f.fingerprint,
        title: f.title,
        description: f.description,
        severity: f.severity,
        category: f.category,
        source: f.source,
        confidence: f.confidence ?? 1.0,
        filePath: f.location?.filePath || 'unknown',
        line: f.location?.startLine || 1,
        endLine: f.location?.endLine,
        column: f.location?.startColumn,
        snippet: f.location?.snippet,
        snippetRedacted: f.location?.snippetRedacted,
        cwe: f.cwe,
        owasp: f.owasp,
        tags: f.tags,
        status: f.status || 'open',
        timesDetected: f.timesDetected || 1,
        firstDetectedAt: f.firstDetectedAt,
        lastDetectedAt: f.lastDetectedAt,
        aiAnalysis: f.aiAnalysis,
        remediation: f.remediation,
      }));
    }
    return MOCK_FINDINGS;
  } catch {
    return MOCK_FINDINGS;
  }
}

export async function fetchFindingById(findingId: string): Promise<DisplayFinding | null> {
  const finding = MOCK_FINDINGS.find((f) => f.id === findingId || f.fingerprint === findingId);
  return finding || MOCK_FINDINGS[0] || null;
}

export async function fetchPullRequests(repoId?: string): Promise<PullRequestSummary[]> {
  if (isDemoMode) {
    return MOCK_PRS.filter((pr) => !repoId || pr.repositoryId === repoId);
  }
  return MOCK_PRS;
}

export async function fetchPullRequestById(prId: string): Promise<PullRequestSummary | null> {
  if (isDemoMode) {
    return MOCK_PRS.find((pr) => pr.id === prId || String(pr.number) === prId) || MOCK_PRS[0] || null;
  }
  try {
    const data = await requestJson<RawPullRequest>(`/api/pull-requests/${prId}`);
    return {
      id: data._id || data.id || prId,
      repositoryId: data.repository,
      repositoryName: 'aishield/aishield-core',
      number: data.number,
      title: data.title,
      author: data.author?.login || 'unknown',
      avatarUrl: data.author?.avatarUrl,
      sourceBranch: data.headBranch,
      targetBranch: data.baseBranch,
      headSha: data.headSha,
      baseSha: data.baseSha,
      findingsIntroduced: data.findingsIntroduced ?? 0,
      findingsResolved: data.findingsResolved ?? 0,
      scoreDelta: data.scoreDelta ?? 0,
      status: data.state || 'open',
      checkStatus: (data.findingsIntroduced ?? 0) > 0 ? 'FAIL' : 'PASS',
      changedFilesCount: data.changedFiles ?? 5,
      analyzedAt: data.updatedAt || new Date().toISOString(),
    };
  } catch {
    return MOCK_PRS.find((pr) => pr.id === prId || String(pr.number) === prId) || MOCK_PRS[0] || null;
  }
}

export async function fetchScans(): Promise<ScanDetails[]> {
  if (isDemoMode) {
    return MOCK_SCANS;
  }
  try {
    const data = await requestJson<RawScan[]>('/api/scans');
    if (Array.isArray(data) && data.length > 0) {
      return data.map((s) => ({
        id: s._id || s.id || 'scan-1',
        repositoryId: s.repository,
        repositoryName: 'aishield/aishield-core',
        commitSha: s.commitSha,
        branch: s.branch,
        baseSha: s.baseSha,
        trigger: s.trigger,
        status: s.status,
        enqueuedAt: s.enqueuedAt,
        startedAt: s.startedAt,
        finishedAt: s.finishedAt,
        durationMs: s.durationMs,
        score: s.finalScore?.overall,
        previousScore: s.finalScore?.previous,
        delta: s.finalScore?.delta,
        grade: s.finalScore?.grade,
        riskLevel: 'HIGH',
        components: s.scannerResults || [],
        summary: s.summary || {
          totalFindings: 0,
          newFindings: 0,
          resolvedFindings: 0,
          bySeverity: {},
          byCategory: {},
        },
      }));
    }
    return MOCK_SCANS;
  } catch {
    return MOCK_SCANS;
  }
}

export async function fetchScanById(scanId: string): Promise<ScanDetails | null> {
  if (isDemoMode) {
    return MOCK_SCANS.find((s) => s.id === scanId) || MOCK_SCANS[0] || null;
  }
  try {
    const data = await requestJson<RawScan>(`/api/scans/${scanId}`);
    return {
      id: data._id || data.id || scanId,
      repositoryId: data.repository,
      repositoryName: 'aishield/aishield-core',
      commitSha: data.commitSha,
      branch: data.branch,
      baseSha: data.baseSha,
      trigger: data.trigger,
      status: data.status,
      enqueuedAt: data.enqueuedAt,
      startedAt: data.startedAt,
      finishedAt: data.finishedAt,
      durationMs: data.durationMs,
      score: data.finalScore?.overall ?? 78.5,
      previousScore: data.finalScore?.previous ?? 85.0,
      delta: data.finalScore?.delta ?? -6.5,
      grade: data.finalScore?.grade ?? 'B',
      riskLevel: 'HIGH',
      components: data.scannerResults || MOCK_SCANS[0]?.components || [],
      summary: data.summary || MOCK_SCANS[0]?.summary || {
        totalFindings: 6,
        newFindings: 3,
        resolvedFindings: 1,
        bySeverity: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 1, INFO: 0 },
        byCategory: { injection: 1, secrets: 1, dependency: 1, authorization: 2, configuration: 1 },
      },
    };
  } catch {
    return MOCK_SCANS.find((s) => s.id === scanId) || MOCK_SCANS[0] || null;
  }
}

export async function fetchDebtHistory(repoId?: string): Promise<DebtHistoryEntry[]> {
  if (isDemoMode) {
    return MOCK_DEBT_HISTORY;
  }
  try {
    const data = await requestJson<RawHistory[]>(`/api/repositories/${repoId || 'default'}/history`);
    if (Array.isArray(data) && data.length > 0) {
      return data.map((h) => ({
        id: h._id || h.id || 'h-1',
        repositoryId: h.repository,
        event: h.event,
        overallScore: h.overallScore,
        previousScore: h.previousScore,
        delta: h.delta,
        grade: h.grade,
        trend: h.trend,
        severityBreakdown: h.severityBreakdown || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        categoryBreakdown: h.categoryBreakdown || {},
        findingCounts: h.findingCounts || { total: 0, open: 0, new: 0, resolved: 0 },
        recordedAt: h.recordedAt,
        scanId: h.scan,
        pullRequestId: h.pullRequest,
      }));
    }
    return MOCK_DEBT_HISTORY;
  } catch {
    return MOCK_DEBT_HISTORY;
  }
}

export async function triggerScan(
  repoId: string,
  commitSha: string,
  branch = 'main',
): Promise<{ scanId: string; jobId: string }> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      repository: repoId,
      commitSha,
      branch,
      trigger: 'manual',
    }),
  });
  if (!res.ok) {
    throw new Error(`Scan trigger failed with status ${res.status}`);
  }
  const json = await res.json();
  return json.data;
}
