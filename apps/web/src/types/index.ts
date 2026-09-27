import type {
  NormalizedCategory,
  NormalizedSeverity,
  ScannerId,
  ScannerStatus,
  SecurityCheckStatus,
} from '@aishield/shared';

export type Severity = NormalizedSeverity;
export type FindingCategory = NormalizedCategory | string;

export interface RepositorySummary {
  id: string;
  name: string;
  fullName: string;
  defaultBranch: string;
  primaryLanguage?: string;
  currentScore: number;
  currentGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  previousScore?: number;
  scoreDelta?: number;
  totalDebtPoints: number;
  activeFindingsCount: number;
  criticalFindingsCount: number;
  highFindingsCount: number;
  mediumFindingsCount: number;
  lowFindingsCount: number;
  trend: 'improving' | 'stable' | 'worsening';
  lastScannedAt?: string;
  lastScanStatus?: string;
  scanEnabled: boolean;
}

export interface PullRequestSummary {
  id: string;
  repositoryId: string;
  repositoryName: string;
  number: number;
  title: string;
  author: string;
  avatarUrl?: string;
  sourceBranch: string;
  targetBranch: string;
  headSha: string;
  baseSha?: string;
  findingsIntroduced: number;
  findingsResolved: number;
  scoreDelta: number;
  status: 'open' | 'closed' | 'merged';
  checkStatus?: SecurityCheckStatus;
  changedFilesCount?: number;
  analyzedAt: string;
}

export interface ComponentStatusInfo {
  source: ScannerId;
  status: ScannerStatus;
  toolVersion?: string;
  durationMs: number;
  findingCount: number;
  error?: string;
}

export interface ScanDetails {
  id: string;
  repositoryId: string;
  repositoryName: string;
  commitSha: string;
  branch: string;
  baseSha?: string;
  trigger: string;
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  enqueuedAt: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  score?: number;
  previousScore?: number;
  delta?: number;
  grade?: 'A' | 'B' | 'C' | 'D' | 'F';
  riskLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  components: ComponentStatusInfo[];
  summary: {
    totalFindings: number;
    newFindings: number;
    resolvedFindings: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
  };
  formulaSummary?: string;
  findingIds?: string[];
}

export interface DisplayFinding {
  id: string;
  repositoryId: string;
  fingerprint: string;
  title: string;
  description?: string;
  severity: Severity;
  category: FindingCategory;
  source: ScannerId | string;
  confidence: number;
  filePath: string;
  line: number;
  endLine?: number;
  column?: number;
  snippet?: string;
  snippetRedacted?: boolean;
  cwe?: string;
  owasp?: string;
  tags?: string[];
  status: 'open' | 'fixed' | 'false_positive' | 'ignored' | 'risk_accepted';
  isNewInPr?: boolean;
  timesDetected: number;
  firstDetectedAt: string;
  lastDetectedAt: string;
  // AI context
  aiAnalysis?: {
    summary?: string;
    exploitability?: 'low' | 'medium' | 'high';
    reachability?: 'reachable' | 'unreachable' | 'unknown';
    businessImpact?: string;
    falsePositiveLikelihood?: number;
    confidence?: number;
  };
  // Remediation
  remediation?: {
    summary?: string;
    steps?: string[];
    effort?: 'trivial' | 'small' | 'medium' | 'large';
    autoFixAvailable?: boolean;
    suggestedPatch?: string;
  };
}

export interface DebtHistoryEntry {
  id: string;
  repositoryId: string;
  event: 'baseline' | 'scan_completed' | 'manual_recalculation' | 'remediation_applied';
  overallScore: number;
  previousScore?: number;
  delta?: number;
  grade?: 'A' | 'B' | 'C' | 'D' | 'F';
  trend?: 'improving' | 'stable' | 'worsening';
  severityBreakdown: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFO: number;
  };
  categoryBreakdown: Record<string, number>;
  findingCounts: {
    total: number;
    open: number;
    new: number;
    resolved: number;
  };
  recordedAt: string;
  scanId?: string;
  pullRequestId?: string;
}

export interface PaginationInfo {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export type PageRoute =
  | { name: 'dashboard' }
  | { name: 'repository'; repoId?: string }
  | { name: 'pull-request'; prId: string }
  | { name: 'scan-details'; scanId: string }
  | { name: 'finding-details'; findingId: string }
  | { name: 'debt-history'; repoId?: string };
