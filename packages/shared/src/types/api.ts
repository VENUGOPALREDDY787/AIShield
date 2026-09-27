/** Envelope returned for every successful API response. */
export interface ApiSuccess<T> {
  readonly data: T;
  readonly requestId?: string;
}

/** Envelope returned for every failed API response. */
export interface ApiErrorBody {
  readonly error: {
    readonly code: string;
    /** Human-readable, safe to surface in the UI. */
    readonly message: string;
    readonly details?: unknown;
    readonly requestId?: string;
  };
}

export type ApiResponse<T> = ApiSuccess<T> | ApiErrorBody;

export type DependencyStatus = 'up' | 'down';

export interface DependencyCheck {
  readonly status: DependencyStatus;
  readonly latencyMs?: number;
  readonly message?: string;
}

/**
 * Body of `GET /health` (liveness) and `GET /health/ready` (readiness).
 * `checks` is only present on the readiness probe.
 */
export interface HealthResponse {
  readonly status: 'ok' | 'degraded';
  readonly service: string;
  readonly version: string;
  readonly environment: string;
  readonly uptimeSeconds: number;
  readonly timestamp: string;
  readonly checks?: Readonly<Record<string, DependencyCheck>>;
}

export interface Paginated<T> {
  readonly items: readonly T[];
  readonly page: number;
  readonly pageSize: number;
  readonly total: number;
}

/** Standard query parameters for collection endpoints. */
export interface PaginationQuery {
  readonly page?: number;
  readonly pageSize?: number;
}
