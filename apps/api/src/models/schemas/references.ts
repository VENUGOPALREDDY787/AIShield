/**
 * External reference subschema, shared by findings and remediation suggestions.
 *
 * Only http(s) documentation links ever belong here — never a URL that embeds a
 * credential (a token in a query string is a secret in the database).
 */
import { Schema } from 'mongoose';

export const referenceSchema = new Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 300 },
    url: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1000,
      match: [/^https:\/\/[^\s]+$/, 'reference url must be an https URL'],
    },
  },
  { _id: false },
);
