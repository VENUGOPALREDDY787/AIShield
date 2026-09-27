import type { LLMProvider, LLMRequestOptions } from '../types.js';

export interface OpenAIProviderConfig {
  readonly apiKey?: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly maxRetries?: number;
  readonly timeoutMs?: number;
}

export class OpenAIProvider implements LLMProvider {
  readonly name = 'openai';
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly defaultTimeoutMs: number;

  constructor(config: OpenAIProviderConfig = {}) {
    this.apiKey = config.apiKey || process.env.OPENAI_API_KEY || process.env.AI_API_KEY || '';
    this.model = config.model || process.env.AI_MODEL || 'gpt-4o-mini';
    this.baseUrl = config.baseUrl || process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1';
    this.maxRetries = config.maxRetries ?? 2;
    this.defaultTimeoutMs = config.timeoutMs ?? 30000;
  }

  async generateText(
    systemPrompt: string,
    userPrompt: string,
    options: LLMRequestOptions = {},
  ): Promise<string> {
    if (!this.apiKey) {
      throw new Error('OpenAI API key is not configured (OPENAI_API_KEY or AI_API_KEY required)');
    }

    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const url = `${this.baseUrl}/chat/completions`;

    const body = {
      model: this.model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      response_format: { type: 'json_object' },
      temperature: 0.1,
    };

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= this.maxRetries) {
      const abortController = new AbortController();
      const timer = setTimeout(() => {
        abortController.abort(new Error(`OpenAI API call timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      if (options.signal) {
        options.signal.addEventListener('abort', () => abortController.abort(options.signal?.reason));
      }

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify(body),
          signal: abortController.signal,
        });

        clearTimeout(timer);

        if (!response.ok) {
          const errText = await response.text().catch(() => '');
          const isTransient = response.status === 429 || (response.status >= 500 && response.status <= 599);

          if (isTransient && attempt < this.maxRetries) {
            attempt++;
            const backoffMs = Math.min(1000 * Math.pow(2, attempt), 4000);
            await new Promise((r) => setTimeout(r, backoffMs));
            continue;
          }

          throw new Error(`OpenAI API error (HTTP ${response.status}): ${errText}`);
        }

        const data = (await response.json()) as {
          choices?: Array<{
            message?: {
              content?: string;
            };
          }>;
        };

        const content = data.choices?.[0]?.message?.content;
        if (!content) {
          throw new Error('OpenAI API returned an empty choices content');
        }

        return content;
      } catch (err) {
        clearTimeout(timer);
        lastError = err instanceof Error ? err : new Error(String(err));

        if (attempt < this.maxRetries && !abortController.signal.aborted) {
          attempt++;
          const backoffMs = Math.min(1000 * Math.pow(2, attempt), 4000);
          await new Promise((r) => setTimeout(r, backoffMs));
          continue;
        }

        throw lastError;
      }
    }

    throw lastError || new Error('OpenAI API call failed after retries');
  }
}
