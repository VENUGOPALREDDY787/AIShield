import { z } from 'zod';
import type { AIAnalysisOutput } from './types.js';

export const aiFindingSchema = z.object({
  category: z.enum(['security', 'debt', 'ai-reasoning']),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5000),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.number().min(0).max(1),
  file: z.string().min(1),
  line: z.number().int().min(1),
  evidence: z.string(),
  remediation: z.string().min(1).max(2000),
  reasoning_summary: z.string().min(1).max(2000),
});

export const aiAnalysisOutputSchema = z.object({
  findings: z.array(aiFindingSchema),
});

/**
 * Extracts and parses JSON from raw LLM output, stripping Markdown code fences if present.
 */
export function extractAndParseJson(rawText: string): unknown {
  if (!rawText || typeof rawText !== 'string') {
    throw new Error('LLM output is empty or not a string');
  }

  let text = rawText.trim();

  // Strip Markdown code fences: ```json ... ``` or ``` ... ```
  if (text.startsWith('```')) {
    text = text.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
  }

  // Find first '{' and last '}'
  const startIdx = text.indexOf('{');
  const endIdx = text.lastIndexOf('}');

  if (startIdx === -1 || endIdx === -1 || endIdx < startIdx) {
    throw new Error('LLM output does not contain a valid JSON object structure');
  }

  const jsonSubstring = text.slice(startIdx, endIdx + 1);

  try {
    return JSON.parse(jsonSubstring);
  } catch (err) {
    throw new Error(`Failed to parse LLM response as JSON: ${err instanceof Error ? err.message : String(err)}`, {
      cause: err,
    });
  }
}

/**
 * Validates parsed JSON against the strict aiAnalysisOutputSchema.
 * Throws a descriptive validation error if the output does not conform.
 */
export function validateAIOutput(parsed: unknown): AIAnalysisOutput {
  const result = aiAnalysisOutputSchema.safeParse(parsed);
  if (!result.success) {
    const errorDetails = result.error.issues
      .map((i) => `  • ${i.path.join('.') || 'root'}: ${i.message}`)
      .join('\n');
    throw new Error(`LLM output failed schema validation:\n${errorDetails}`);
  }
  return result.data;
}
