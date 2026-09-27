import { normalizeAIFindings } from './normalizer.js';
import { SYSTEM_SECURITY_ANALYST_PROMPT, buildUserPrompt } from './prompts/context-analysis.prompt.js';
import { createLLMProvider } from './providers/provider-factory.js';
import { extractAndParseJson, validateAIOutput } from './schema.js';
import type {
  AIAnalysisRequest,
  AIAnalysisResponse,
  LLMProvider,
  LLMProviderConfig,
} from './types.js';
import type { NormalizedFinding } from '@aishield/shared';

export class AIContextualAnalyzer {
  readonly provider: LLMProvider;
  readonly modelName: string;
  private readonly defaultTimeoutMs: number;

  constructor(configOrProvider?: Partial<LLMProviderConfig> | LLMProvider) {
    if (configOrProvider && typeof (configOrProvider as LLMProvider).generateText === 'function') {
      this.provider = configOrProvider as LLMProvider;
      this.modelName = this.provider.model;
      this.defaultTimeoutMs = 30000;
    } else {
      const config = (configOrProvider as Partial<LLMProviderConfig>) || {};
      const providerName = config.provider || process.env.AI_PROVIDER || 'gemini';
      const model = config.model || process.env.AI_MODEL || (providerName === 'openai' ? 'gpt-4o-mini' : 'gemini-2.5-flash');

      this.defaultTimeoutMs = config.timeoutMs ?? parseInt(process.env.AI_TIMEOUT_MS || '30000', 10);
      this.provider = createLLMProvider({
        provider: providerName,
        model,
        apiKey: config.apiKey,
        baseUrl: config.baseUrl,
        timeoutMs: this.defaultTimeoutMs,
        maxRetries: config.maxRetries ?? parseInt(process.env.AI_MAX_RETRIES || '2', 10),
      });
      this.modelName = model;
    }
  }

  /**
   * Performs contextual LLM analysis on the provided code changes.
   * Tolerates errors and timeouts without throwing unhandled exceptions.
   */
  async analyze(request: AIAnalysisRequest): Promise<AIAnalysisResponse> {
    const started = Date.now();

    // Skip analysis if diff content is completely empty
    if (!request.diffContent || request.diffContent.trim().length === 0) {
      return {
        status: 'succeeded',
        findings: [],
        model: this.modelName,
        provider: this.provider.name,
        durationMs: Date.now() - started,
      };
    }

    try {
      // 1. Build minimized, secret-redacted prompt
      const userPrompt = buildUserPrompt(request);

      // 2. Query LLM provider with timeout and retry handling
      const rawText = await this.provider.generateText(
        SYSTEM_SECURITY_ANALYST_PROMPT,
        userPrompt,
        { timeoutMs: this.defaultTimeoutMs },
      );

      // 3. Extract and parse structured JSON
      const parsedJson = extractAndParseJson(rawText);

      // 4. Validate strictly against Zod JSON schema (rejects malformed output)
      const validated = validateAIOutput(parsedJson);

      const durationMs = Date.now() - started;

      return {
        status: 'succeeded',
        findings: validated.findings,
        model: this.modelName,
        provider: this.provider.name,
        durationMs,
      };
    } catch (err) {
      const durationMs = Date.now() - started;
      const errorMessage = err instanceof Error ? err.message : String(err);

      return {
        status: 'failed',
        findings: [],
        model: this.modelName,
        provider: this.provider.name,
        durationMs,
        error: errorMessage,
      };
    }
  }

  /**
   * Convenience method that runs analysis and returns normalized findings ready for ingestion.
   */
  async analyzeAndNormalize(request: AIAnalysisRequest): Promise<{
    status: 'succeeded' | 'failed' | 'skipped';
    findings: NormalizedFinding[];
    durationMs: number;
    error?: string;
  }> {
    const res = await this.analyze(request);

    if (res.status === 'failed') {
      return {
        status: 'failed',
        findings: [],
        durationMs: res.durationMs,
        error: res.error,
      };
    }

    const normalized = normalizeAIFindings(res.findings, {
      model: res.model,
      provider: res.provider,
      scanId: request.scanId,
    });

    return {
      status: 'succeeded',
      findings: normalized,
      durationMs: res.durationMs,
    };
  }
}
