/**
 * Request-scoped type additions.
 *
 * The API exposes `requestId` / `logger` (rather than pino-http's own `id` /
 * `log`) so the correlation id stays ours to control. Augmenting
 * `http.IncomingMessage` covers Express's `Request` too, because Express
 * extends it — which also makes these fields visible inside pino-http
 * callbacks that are typed against the raw Node request.
 */
import type { Logger } from 'pino';

declare module 'http' {
  interface IncomingMessage {
    /** Correlation id assigned by the requestContext middleware. */
    requestId: string;
    /** Child logger bound to this request's correlation id. */
    logger: Logger;
    /**
     * Authentication context set by the authenticate middleware.
     * Present after successful authentication; absent on unauthenticated paths.
     */
    auth?: {
      userId: string;
      role: 'admin' | 'member' | 'viewer';
      method: 'api-key' | 'dev-bypass';
    };
  }
}

export {};
