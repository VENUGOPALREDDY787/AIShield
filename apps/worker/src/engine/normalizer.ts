import type { NormalizedCategory, NormalizedSeverity } from '@aishield/shared';

/**
 * Standard severity ranking for comparison: CRITICAL > HIGH > MEDIUM > LOW > INFO
 */
export const SEVERITY_RANKS: Readonly<Record<NormalizedSeverity, number>> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/**
 * Compares two normalized severities. Returns positive if a > b, negative if a < b, 0 if equal.
 */
export function compareSeverities(a: NormalizedSeverity, b: NormalizedSeverity): number {
  return (SEVERITY_RANKS[a] ?? 0) - (SEVERITY_RANKS[b] ?? 0);
}

/**
 * Returns the higher of two normalized severities.
 */
export function maxSeverity(a: NormalizedSeverity, b: NormalizedSeverity): NormalizedSeverity {
  return compareSeverities(a, b) >= 0 ? a : b;
}

/**
 * Normalizes any scanner severity string, numeric CVSS score, or alias to canonical
 * CRITICAL | HIGH | MEDIUM | LOW | INFO.
 */
export function normalizeSeverity(
  input: unknown,
  fallback: NormalizedSeverity = 'MEDIUM',
): NormalizedSeverity {
  if (input === null || input === undefined) {
    return fallback;
  }

  // Handle numeric CVSS score (e.g. 9.8, 7.5, 5.0)
  if (typeof input === 'number') {
    if (Number.isNaN(input)) return fallback;
    if (input >= 9.0) return 'CRITICAL';
    if (input >= 7.0) return 'HIGH';
    if (input >= 4.0) return 'MEDIUM';
    if (input > 0.0) return 'LOW';
    return 'INFO';
  }

  const str = String(input).trim().toUpperCase();

  switch (str) {
    // CRITICAL
    case 'CRITICAL':
    case 'CRIT':
    case 'BLOCKER':
    case 'FATAL':
    case 'P0':
    case 'SEVERITY_CRITICAL':
      return 'CRITICAL';

    // HIGH
    case 'HIGH':
    case 'ERROR':
    case 'MAJOR':
    case 'P1':
    case 'SEVERE':
    case 'SEVERITY_HIGH':
      return 'HIGH';

    // MEDIUM
    case 'MEDIUM':
    case 'MED':
    case 'MODERATE':
    case 'WARNING':
    case 'WARN':
    case 'P2':
    case 'SEVERITY_MEDIUM':
      return 'MEDIUM';

    // LOW
    case 'LOW':
    case 'MINOR':
    case 'NOTICE':
    case 'NEGLIGIBLE':
    case 'P3':
    case 'SEVERITY_LOW':
      return 'LOW';

    // INFO
    case 'INFO':
    case 'INFORMATIONAL':
    case 'INFORMATION':
    case 'NOTE':
    case 'LOWEST':
    case 'P4':
    case 'DEBUG':
    case 'INVENTORY':
    case 'EXPERIMENT':
    case 'UNKNOWN':
    case 'SEVERITY_INFO':
    case 'UNSPECIFIED':
      return 'INFO';

    default: {
      // Try parsing numeric string if passed like "9.5"
      const num = parseFloat(str);
      if (!Number.isNaN(num)) {
        return normalizeSeverity(num, fallback);
      }
      return fallback;
    }
  }
}

/**
 * Mapping from known CWE numbers to NormalizedCategory.
 */
const CWE_CATEGORY_MAP: Readonly<Record<string, NormalizedCategory>> = {
  // Injection
  'CWE-89': 'injection', // SQLi
  'CWE-79': 'injection', // XSS
  'CWE-94': 'injection', // Code injection
  'CWE-95': 'injection', // Eval injection
  'CWE-91': 'injection', // XML injection
  'CWE-1336': 'injection', // Template injection
  'CWE-502': 'injection', // Deserialization injection
  'CWE-943': 'injection', // Special elements in data query (NoSQL injection)

  // Command Execution
  'CWE-78': 'command_execution', // OS Command injection
  'CWE-77': 'command_execution', // Command injection
  'CWE-88': 'command_execution', // Argument injection

  // Authentication
  'CWE-287': 'authentication', // Improper authentication
  'CWE-306': 'authentication', // Missing authentication
  'CWE-384': 'authentication', // Session fixation
  'CWE-521': 'authentication', // Weak password requirements
  'CWE-640': 'authentication', // Weak password recovery
  'CWE-290': 'authentication', // Authentication bypass by spoofing
  'CWE-307': 'authentication', // Improper restriction of excessive auth attempts

  // Authorization
  'CWE-862': 'authorization', // Missing authorization
  'CWE-863': 'authorization', // Incorrect authorization
  'CWE-285': 'authorization', // Improper authorization
  'CWE-639': 'authorization', // IDOR / Authorization bypass through user-controlled key
  'CWE-732': 'authorization', // Incorrect permission assignment
  'CWE-284': 'authorization', // Improper access control
  'CWE-269': 'authorization', // Improper privilege management

  // Secrets
  'CWE-798': 'secrets', // Use of hardcoded credentials
  'CWE-259': 'secrets', // Use of hardcoded password
  'CWE-312': 'secrets', // Cleartext storage of sensitive information
  'CWE-522': 'secrets', // Insufficiently protected credentials
  'CWE-321': 'secrets', // Use of hardcoded cryptographic key

  // Cryptography
  'CWE-327': 'cryptography', // Broken/risky cryptographic algorithm
  'CWE-328': 'cryptography', // Reversible one-way hash
  'CWE-330': 'cryptography', // Use of insufficiently random values
  'CWE-326': 'cryptography', // Inadequate encryption strength
  'CWE-347': 'cryptography', // Improper verification of cryptographic signature
  'CWE-916': 'cryptography', // Use of password hash with insufficient computational effort
  'CWE-757': 'cryptography', // Selection of less-secure algorithm
  'CWE-310': 'cryptography', // Cryptographic issues

  // Data Exposure
  'CWE-200': 'data_exposure', // Exposure of sensitive information
  'CWE-209': 'data_exposure', // Generation of error message containing sensitive information
  'CWE-215': 'data_exposure', // Insertion of sensitive information into debug code
  'CWE-532': 'data_exposure', // Insertion of sensitive info into log file
  'CWE-548': 'data_exposure', // Exposure through directory listing
  'CWE-598': 'data_exposure', // Use of GET request method with sensitive query strings
  'CWE-497': 'data_exposure', // Exposure of system data to an unauthorized control sphere

  // Dependency
  'CWE-1395': 'dependency', // Use of vulnerable third-party component
  'CWE-1104': 'dependency', // Use of unmaintained third-party component
  'CWE-937': 'dependency', // Using components with known vulnerabilities

  // Input Validation
  'CWE-20': 'input_validation', // Improper input validation
  'CWE-22': 'input_validation', // Path traversal
  'CWE-125': 'input_validation', // Out-of-bounds read
  'CWE-787': 'input_validation', // Out-of-bounds write
  'CWE-120': 'input_validation', // Buffer copy without size check
  'CWE-400': 'input_validation', // Uncontrolled resource consumption
  'CWE-776': 'input_validation', // XML entity expansion (Billion Laughs)
  'CWE-601': 'input_validation', // Open redirect
  'CWE-116': 'input_validation', // Improper encoding or escaping of output

  // Configuration
  'CWE-16': 'configuration', // Configuration
  'CWE-1004': 'configuration', // Sensitive cookie without 'HttpOnly' flag
  'CWE-611': 'configuration', // XXE through improper XML parser configuration
  'CWE-1021': 'configuration', // Improper restriction of render frames (Clickjacking)
  'CWE-942': 'configuration', // Overly permissive CORS policy
  'CWE-693': 'configuration', // Protection mechanism failure
  'CWE-319': 'configuration', // Cleartext transmission of sensitive information
  'CWE-523': 'configuration', // Unprotected transport of credentials

  // Business Logic
  'CWE-840': 'business_logic', // Business logic errors
  'CWE-841': 'business_logic', // Improper enforcement of behavioral workflow
  'CWE-362': 'business_logic', // Race condition / concurrent execution
  'CWE-829': 'business_logic', // Inclusion of functionality from untrusted control sphere
  'CWE-434': 'business_logic', // Unrestricted upload of file with dangerous type
};

export interface CategoryClassificationInput {
  category?: unknown;
  ruleId?: unknown;
  cwe?: unknown;
  title?: unknown;
  description?: unknown;
  source?: unknown;
}

/**
 * Normalizes any category, rule ID, CWE, title, and description into one of the canonical 12 categories:
 * injection | authentication | authorization | secrets | cryptography | data_exposure |
 * dependency | input_validation | command_execution | configuration | business_logic | other
 */
export function normalizeCategory(input: CategoryClassificationInput): NormalizedCategory {
  const sourceStr = String(input.source || '').toLowerCase();

  // Tier 1: Source Fast-Paths
  if (sourceStr === 'gitleaks') {
    return 'secrets';
  }
  if (sourceStr === 'dependency' || sourceStr === 'osv' || sourceStr === 'osv-scanner') {
    return 'dependency';
  }

  // Tier 2: Direct match with standard categories
  const rawCat = String(input.category || '')
    .trim()
    .toLowerCase()
    .replace(/[-_]/g, '_');

  if (rawCat) {
    switch (rawCat) {
      case 'injection':
        return 'injection';
      case 'authentication':
      case 'authn':
        return 'authentication';
      case 'authorization':
      case 'authz':
      case 'access_control':
        return 'authorization';
      case 'secrets':
      case 'secret':
      case 'credentials':
        return 'secrets';
      case 'cryptography':
      case 'crypto':
        return 'cryptography';
      case 'data_exposure':
      case 'data_leak':
      case 'leak':
        return 'data_exposure';
      case 'dependency':
      case 'dependencies':
        return 'dependency';
      case 'input_validation':
      case 'validation':
        return 'input_validation';
      case 'command_execution':
      case 'command_injection':
      case 'rce':
        return 'command_execution';
      case 'configuration':
      case 'config':
      case 'misconfiguration':
        return 'configuration';
      case 'business_logic':
      case 'logic':
      case 'debt':
        return 'business_logic';
      case 'other':
        return 'other';
    }
  }

  // Tier 3: CWE Lookup
  const cweStr = String(input.cwe || '').toUpperCase().trim();
  if (cweStr) {
    const match = cweStr.match(/CWE-\d+/);
    if (match && match[0]) {
      const mapped = CWE_CATEGORY_MAP[match[0]];
      if (mapped) {
        return mapped;
      }
    }
  }

  // Tier 4: Keyword & Regex heuristics over ruleId, title, and description
  const combinedText = `${input.ruleId || ''} ${input.title || ''} ${input.description || ''}`.toLowerCase();

  // Command execution check (before general injection to distinguish exec from sqli)
  if (
    /(command[\s-_]?inject|os[\s-_]?command|system[\s-_]?command|shell[\s-_]?inject|\b(exec|spawn|popen|system|child_process|command\s+execution)\b)/i.test(
      combinedText,
    )
  ) {
    return 'command_execution';
  }

  // Secrets check
  if (
    /(gitleaks|aws[\s-_]?(access[\s-_]?)?key|github[\s-_]?token|slack[\s-_]?token|private[\s-_]?key|hardcoded[\s-_]?(password|token|secret|key|credential)|api[\s-_]?(key|token)|secret[\s-_]?leak)/i.test(
      combinedText,
    )
  ) {
    return 'secrets';
  }

  // Dependency check
  if (
    /(cve-\d+|ghsa-[a-z0-9-]+|npm[\s-_]?audit|vulnerable[\s-_]?(package|dependency|component)|outdated|osv)/i.test(
      combinedText,
    )
  ) {
    return 'dependency';
  }

  // Injection check
  if (
    /\b(sql|sqli|xss|nosql|ldap|xpath|template[\s-_]?injection|eval[\s-_]?injection|ssti)\b|injection/i.test(
      combinedText,
    )
  ) {
    return 'injection';
  }

  // Authorization check (IDOR, role check, privilege escalation)
  if (
    /(idor|rbac|abac|authorization|authz|privilege[\s-_]?escalation|access[\s-_]?control|permission[\s-_]?check|ownership[\s-_]?check|missing[\s-_]?authz|insecure\s+direct\s+object\s+reference)/i.test(
      combinedText,
    )
  ) {
    return 'authorization';
  }

  // Authentication check (login, session, JWT, password verification)
  if (
    /\b(authentication|authn|login|session[\s-_]?fixation|jwt|bearer|oauth|password[\s-_]?reset|credential[\s-_]?stuffing|mfa)\b/i.test(
      combinedText,
    )
  ) {
    return 'authentication';
  }

  // Cryptography check
  if (
    /\b(crypto|cryptography|weak[\s-_]?cipher|md5|sha1|des|aes[\s-_]?ecb|hardcoded[\s-_]?salt|insecure[\s-_]?random|prng)\b/i.test(
      combinedText,
    )
  ) {
    return 'cryptography';
  }

  // Data Exposure check
  if (
    /(data[\s-_]?exposure|information[\s-_]?disclosure|leak|pii|credit[\s-_]?card|stack[\s-_]?trace|verbose[\s-_]?error|sensitive[\s-_]?data)/i.test(
      combinedText,
    )
  ) {
    return 'data_exposure';
  }

  // Input Validation check
  if (
    /(input[\s-_]?validation|path[\s-_]?traversal|directory[\s-_]?traversal|redos|regex[\s-_]?dos|untrusted[\s-_]?input|open[\s-_]?redirect|boundary[\s-_]?check)/i.test(
      combinedText,
    )
  ) {
    return 'input_validation';
  }

  // Configuration check
  if (
    /(cors|csrf|security[\s-_]?header|content[\s-_]?security[\s-_]?policy|debug[\s-_]?mode|tls|ssl|insecure[\s-_]?cookie|httponly|samesite|permissive\s+cors)/i.test(
      combinedText,
    )
  ) {
    return 'configuration';
  }

  // Business Logic check
  if (
    /(business[\s-_]?logic|workflow[\s-_]?bypass|race[\s-_]?condition|tamper(ing)?|payment[\s-_]?flow|order[\s-_]?validation|discount[\s-_]?bypass|price\s+tampering)/i.test(
      combinedText,
    )
  ) {
    return 'business_logic';
  }

  return 'other';
}

/**
 * Normalizes confidence scores into a reliable 0.0 - 1.0 float.
 */
export function normalizeConfidence(
  confidence: unknown,
  source?: string,
  metadata?: Record<string, unknown>,
): number {
  if (typeof confidence === 'number') {
    if (Number.isNaN(confidence)) return 0.8;
    return Math.min(1.0, Math.max(0.0, Number(confidence.toFixed(2))));
  }

  if (typeof confidence === 'string') {
    const upper = confidence.trim().toUpperCase();
    if (upper === 'HIGH' || upper === 'VERY_HIGH') return 0.95;
    if (upper === 'MEDIUM' || upper === 'MODERATE') return 0.8;
    if (upper === 'LOW') return 0.65;
    const parsed = parseFloat(upper);
    if (!Number.isNaN(parsed)) {
      return Math.min(1.0, Math.max(0.0, Number(parsed.toFixed(2))));
    }
  }

  // Check metadata for Semgrep confidence
  if (metadata && typeof metadata.confidence === 'string') {
    const metaConf = String(metadata.confidence).toUpperCase();
    if (metaConf === 'HIGH') return 0.95;
    if (metaConf === 'MEDIUM') return 0.8;
    if (metaConf === 'LOW') return 0.65;
  }

  // Source default guarantees
  const src = String(source || '').toLowerCase();
  switch (src) {
    case 'dependency':
    case 'osv':
      return 1.0; // Known CVEs in manifest/lockfile are authoritative
    case 'gitleaks':
      return 0.95; // Exact secret pattern match
    case 'semgrep':
      return 0.9; // AST rule match
    case 'ai-analyzer':
      return 0.8; // Contextual suggestion
    default:
      return 0.8;
  }
}

/**
 * Combines two independent confidence values using probabilistic union:
 * C_combined = 1 - (1 - c1) * (1 - c2)
 * Ensures that two agreeing sources reflect higher corroboration.
 */
export function combineConfidence(c1: number, c2: number): number {
  const clamped1 = Math.min(1.0, Math.max(0.0, c1));
  const clamped2 = Math.min(1.0, Math.max(0.0, c2));
  const combined = 1 - (1 - clamped1) * (1 - clamped2);
  return Math.min(1.0, Math.max(0.0, Number(combined.toFixed(3))));
}
