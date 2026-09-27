import type { LLMProvider, LLMRequestOptions } from '../types.js';

export interface GeminiProviderConfig {
  readonly apiKey?: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly maxRetries?: number;
  readonly timeoutMs?: number;
}

export class GeminiProvider implements LLMProvider {
  readonly name = 'gemini';
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly maxRetries: number;
  private readonly defaultTimeoutMs: number;

  constructor(config: GeminiProviderConfig = {}) {
    this.apiKey = config.apiKey || process.env.GEMINI_API_KEY || process.env.AI_API_KEY || '';
    this.model = config.model || process.env.AI_MODEL || 'gemini-2.5-flash';
    this.baseUrl = config.baseUrl || 'https://generativelanguage.googleapis.com/v1beta';
    this.maxRetries = config.maxRetries ?? 2;
    this.defaultTimeoutMs = config.timeoutMs ?? 30000;
  }

  async generateText(
    systemPrompt: string,
    userPrompt: string,
    options: LLMRequestOptions = {},
  ): Promise<string> {
    if (!this.apiKey) {
      throw new Error('Gemini API key is not configured (GEMINI_API_KEY or AI_API_KEY required)');
    }

    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const url = `${this.baseUrl}/models/${encodeURIComponent(this.model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;

    const body = {
      systemInstruction: {
        parts: [{ text: systemPrompt }],
      },
      contents: [
        {
          role: 'user',
          parts: [{ text: userPrompt }],
        },
      ],
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.1,
      },
    };

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt <= this.maxRetries) {
      const abortController = new AbortController();
      const timer = setTimeout(() => {
        abortController.abort(new Error(`Gemini API call timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      if (options.signal) {
        options.signal.addEventListener('abort', () => abortController.abort(options.signal?.reason));
      }

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
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

          throw new Error(`Gemini API error (HTTP ${response.status}): ${errText}`);
        }

        const data = (await response.json()) as {
          candidates?: Array<{
            content?: {
              parts?: Array<{ text?: string }>;
            };
          }>;
        };

        const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        if (!candidateText) {
          throw new Error('Gemini API returned an empty candidate response');
        }

        return candidateText;
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

    throw lastError || new Error('Gemini API call failed after retries');
  }
}
