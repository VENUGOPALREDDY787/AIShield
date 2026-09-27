/**
 * Security validation and sanitization helpers for AIShield.
 * Enforces zero-trust boundaries on untrusted repository input, URLs, and git metadata.
 */

const PRIVATE_IP_PATTERNS = [
  /^127\./, // Loopback IPv4
  /^0\./, // Current network
  /^10\./, // RFC 1918 Class A
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // RFC 1918 Class B
  /^192\.168\./, // RFC 1918 Class C
  /^169\.254\./, // Link-local / Cloud Metadata (AWS, GCP, Azure)
  /^::1$/, // IPv6 loopback
  /^fe80:/i, // IPv6 link-local
  /^fc00:/i, // IPv6 unique local
  /^fd00:/i, // IPv6 unique local
  /^localhost$/i,
];

/**
 * Validates a git commit SHA (short 7-char or full 40-char hex string).
 */
export function isValidGitSha(sha: string): boolean {
  if (!sha || typeof sha !== 'string') return false;
  return /^[0-9a-fA-F]{7,40}$/.test(sha.trim());
}

/**
 * Validates a git ref/branch name to prevent argument injection and malformed git operations.
 */
export function isValidGitRef(ref: string): boolean {
  if (!ref || typeof ref !== 'string') return false;
  const trimmed = ref.trim();
  // Reject leading dash/flag or dot
  if (trimmed.startsWith('-') || trimmed.startsWith('.')) return false;
  // Must only contain alphanumeric characters, underscores, hyphens, dots, or slashes
  if (!/^[a-zA-Z0-9_./-]+$/.test(trimmed)) return false;
  if (trimmed.includes('..') || trimmed.includes('//') || trimmed.endsWith('/')) return false;
  return trimmed.length > 0 && trimmed.length <= 255;
}

/**
 * Validates a repository URL to prevent SSRF against internal services, cloud metadata endpoints,
 * and loopback interfaces.
 */
export function validateRepositoryUrl(rawUrl: string): { valid: boolean; reason?: string } {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, reason: 'URL is required' };
  }

  const trimmed = rawUrl.trim();

  // Allow standard SCP-style git URLs: git@github.com:owner/repo.git or git@gitlab.com:owner/repo.git
  if (/^git@[a-zA-Z0-9.-]+:[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+(\.git)?$/.test(trimmed)) {
    const host = trimmed.split('@')[1]?.split(':')[0]?.toLowerCase();
    if (host && PRIVATE_IP_PATTERNS.some((p) => p.test(host))) {
      return { valid: false, reason: 'Private/internal hostnames are forbidden' };
    }
    return { valid: true };
  }

  try {
    const parsed = new URL(trimmed);

    // Only allow HTTPS or standard SSH protocols
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'ssh:') {
      return { valid: false, reason: `Forbidden protocol "${parsed.protocol}" (only https: is allowed)` };
    }

    // Clean IPv6 brackets if present
    const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

    // Check against loopback, cloud metadata (169.254.169.254), and private subnets
    if (PRIVATE_IP_PATTERNS.some((pattern) => pattern.test(hostname))) {
      return { valid: false, reason: 'Private IP addresses and metadata endpoints are blocked (SSRF guard)' };
    }

    // Block non-standard HTTP ports for repository clones
    if (parsed.port && parsed.port !== '443' && parsed.port !== '22') {
      return { valid: false, reason: `Non-standard port "${parsed.port}" is not permitted` };
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: 'Invalid URL format' };
  }
}

/**
 * Sanitizes and validates a relative file path to prevent directory traversal out of the workspace.
 */
export function sanitizeRelativePath(filePath: string): string | null {
  if (!filePath || typeof filePath !== 'string') return null;

  const rawTrimmed = filePath.trim();

  // Reject absolute paths starting with / or \ or drive letter (C:)
  if (rawTrimmed.startsWith('/') || rawTrimmed.startsWith('\\') || /^[a-zA-Z]:/.test(rawTrimmed)) {
    return null;
  }

  let cleaned = rawTrimmed.replace(/\\/g, '/');

  // Strip leading dot-slash
  while (cleaned.startsWith('./')) {
    cleaned = cleaned.slice(2);
  }

  // Reject paths that attempt parent directory traversal or start with flags
  const segments = cleaned.split('/');
  if (segments.some((s) => s === '..' || s === '' || s.startsWith('-'))) {
    return null;
  }

  return cleaned;
}
