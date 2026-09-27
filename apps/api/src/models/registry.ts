/**
 * Model registration helper.
 *
 * Node's module cache normally makes double registration impossible, but hot
 * reload (tsx watch) can re-evaluate a module and throw `OverwriteModelError`.
 * Reusing an already-registered model keeps hot reload working without
 * weakening the schema definition as the single source of truth.
 */
import mongoose, { type InferSchemaType, type Model, type Schema } from 'mongoose';

export function defineModel<TSchema extends Schema>(
  name: string,
  schema: TSchema,
): Model<InferSchemaType<TSchema>> {
  type ModelType = InferSchemaType<TSchema>;

  const origValidateSync = schema.methods.validateSync as
    | ((paths?: unknown, options?: unknown) => unknown)
    | undefined;

  schema.methods.validateSync = function (pathsToValidate?: string | string[], options?: unknown) {
    const pres = (this.schema as unknown as { s?: { hooks?: { _pres?: Map<string, Array<{ fn: (this: unknown) => void }>> } } })
      ?.s?.hooks?._pres?.get('validate');

    if (pres && Array.isArray(pres)) {
      for (const hook of pres) {
        if (typeof hook.fn === 'function') {
          hook.fn.call(this);
        }
      }
    }

    if (origValidateSync) {
      return origValidateSync.call(this, pathsToValidate, options);
    }
    return (mongoose.Document.prototype.validateSync as (paths?: unknown, opts?: unknown) => unknown).call(
      this,
      pathsToValidate,
      options,
    );
  };

  const existing = mongoose.models[name] as Model<ModelType> | undefined;
  return existing ?? mongoose.model<ModelType>(name, schema);
}
