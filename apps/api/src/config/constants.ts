/** Values that are not deployment-specific configuration. */

/** Mount point for the versioned public API. */
export const API_PREFIX = '/api/v1';

/**
 * Infrastructure probes live outside the versioned API: orchestrators and load
 * balancers should never have to care about our API version.
 */
export const HEALTH_PREFIX = '/health';

/** Reported by the health probe. Keep in sync with package.json. */
export const SERVICE_VERSION = '0.1.0';

/** Correlation id echoed back on every response. */
export const REQUEST_ID_HEADER = 'x-request-id';

/** Grace period allowed for in-flight requests during shutdown. */
export const SHUTDOWN_TIMEOUT_MS = 10_000;
