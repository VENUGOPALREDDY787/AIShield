/**
 * Serialisation plugin applied to every schema.
 *
 * Guarantees that anything leaving the API as JSON has a string `id` instead of
 * `_id`/`__v`, and gives each schema a hook to strip fields that must never
 * reach a client (a password hash, an internal token reference).
 */
import type { Schema } from 'mongoose';

export interface ToJsonPluginOptions {
  /**
   * Top-level paths removed from serialised output. Use this for anything that
   * is not safe to expose even if it was explicitly selected.
   */
  redact?: readonly string[];
}

export function toJsonPlugin(schema: Schema, options: ToJsonPluginOptions = {}): void {
  const redacted = options.redact ?? [];

  const transform = (_doc: unknown, ret: Record<string, unknown>): Record<string, unknown> => {
    for (const path of redacted) {
      delete ret[path];
    }
    if (ret._id !== undefined) {
      ret.id = String(ret._id);
      delete ret._id;
    }
    delete ret.__v;
    return ret;
  };

  schema.set('toJSON', { virtuals: true, versionKey: false, transform });
  // Used when a document is embedded in another document's output.
  schema.set('toObject', { virtuals: true, versionKey: false, transform });
}
