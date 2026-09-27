import type { NormalizedFinding, Severity } from '@aishield/shared';

export interface AIAnalysisRequest {
  readonly scanId: string;
  readonly diffContent: string;
  readonly deterministicFindings?: readonly NormalizedFinding[];
  readonly repositoryContext?: {
    readonly language?: string;
    readonly framework?: string;
    readonly repoName?: string;
  };
  readonly maxDiffLines?: number;
}

export type AICategory = 'security' | 'debt' | 'ai-reasoning';

export interface AIFinding {
  readonly category: AICategory;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: number;
  readonly file: string;
  readonly line: number;
  readonly evidence: string;
  readonly remediation: string;
  readonly reasoning_summary: string;
}

export interface AIAnalysisOutput {
  readonly findings: readonly AIFinding[];
}

export interface AIAnalysisResponse {
  readonly status: 'succeeded' | 'failed' | 'skipped';
  readonly findings: readonly AIFinding[];
  readonly model: string;
  readonly provider: string;
  readonly durationMs: number;
  readonly error?: string;
  readonly tokensUsed?: number;
}

export interface LLMProviderConfig {
  readonly provider: 'gemini' | 'openai' | 'mock' | string;
  readonly model: string;
  readonly apiKey?: string;
  readonly baseUrl?: string;
  readonly timeoutMs?: number;
  readonly maxRetries?: number;
}

export interface LLMRequestOptions {
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}

export interface LLMProvider {
  readonly name: string;
  readonly model: string;
  generateText(systemPrompt: string, userPrompt: string, options?: LLMRequestOptions): Promise<string>;
}
