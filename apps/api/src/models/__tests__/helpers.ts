/**
 * Shared helpers for the model tests.
 *
 * The tests run without a MongoDB connection on purpose: mongoose document
 * validation, defaults, hooks and (de)serialisation are all in-memory
 * operations, so the suite stays fast and deterministic in CI.
 *
 * What that cannot cover is enforcement by the *server*: `unique`, `sparse` and
 * `partialFilterExpression` are only upheld by MongoDB itself. Those tests
 * assert that the index definitions are correct, and the enforcement itself
 * belongs to an integration suite against a real mongod.
 */
import { Types } from 'mongoose';

export function oid(): Types.ObjectId {
  return new Types.ObjectId();
}

interface ValidatableDocument {
  validateSync(): { errors?: Record<string, unknown> } | null | undefined;
}

/**
 * Validation paths that failed, sorted. An empty array means the document is
 * valid. `validateSync` runs `pre('validate')` hooks, so the redaction and
 * derivation logic is exercised too.
 */
export function invalidPaths(doc: ValidatableDocument): string[] {
  const error = doc.validateSync();
  const errors = error?.errors;
  if (!errors) return [];
  return Object.keys(errors).sort();
}

export interface IndexedModel {
  schema: { indexes(): Array<[unknown, unknown]> };
}

export interface IndexDefinition {
  readonly fields: Record<string, unknown>;
  readonly options: Record<string, unknown>;
  /** Convenience: the compound key as `field:direction` pairs. */
  readonly key: string;
}

export function indexesOf(model: IndexedModel): IndexDefinition[] {
  return model.schema.indexes().map(([fields, options]) => {
    const keyParts = Object.entries(fields as Record<string, unknown>).map(
      ([field, direction]) => `${field}:${String(direction)}`,
    );

    return {
      fields: fields as Record<string, unknown>,
      options: (options ?? {}) as Record<string, unknown>,
      key: keyParts.join(','),
    };
  });
}

/** Looks an index up by the explicit `name` every index in this project sets. */
export function indexNamed(model: IndexedModel, name: string): IndexDefinition | undefined {
  return indexesOf(model).find((index) => index.options.name === name);
}
