/**
 * Authentication & API Configuration
 * Remediation: Secure environment variable consumption with safe fallbacks.
 */

// Loaded dynamically from process environment or vault
export const GITHUB_INTEGRATION_TOKEN = process.env.GITHUB_INTEGRATION_TOKEN || '';

// JWT Secret Key loaded from environment
export const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-ephemeral-key-do-not-use-in-prod';

// Cloud Provider Access Key
export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID || '';
