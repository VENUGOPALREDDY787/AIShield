import type { LLMProvider, LLMProviderConfig } from '../types.js';
import { GeminiProvider } from './gemini.provider.js';
import { MockProvider } from './mock.provider.js';
import { OpenAIProvider } from './openai.provider.js';

export function createLLMProvider(config: LLMProviderConfig): LLMProvider {
  const providerName = (config.provider || process.env.AI_PROVIDER || 'gemini').toLowerCase();

  switch (providerName) {
    case 'gemini': {
      const apiKey = config.apiKey || process.env.GEMINI_API_KEY || process.env.AI_API_KEY;
      if (!apiKey && process.env.NODE_ENV === 'test') {
        return new MockProvider({ model: config.model || 'mock-gemini' });
      }
      return new GeminiProvider({
        apiKey,
        model: config.model || process.env.AI_MODEL || 'gemini-2.5-flash',
        baseUrl: config.baseUrl,
        timeoutMs: config.timeoutMs,
        maxRetries: config.maxRetries,
      });
    }

    case 'openai': {
      const apiKey = config.apiKey || process.env.OPENAI_API_KEY || process.env.AI_API_KEY;
      if (!apiKey && process.env.NODE_ENV === 'test') {
        return new MockProvider({ model: config.model || 'mock-openai' });
      }
      return new OpenAIProvider({
        apiKey,
        model: config.model || process.env.AI_MODEL || 'gpt-4o-mini',
        baseUrl: config.baseUrl,
        timeoutMs: config.timeoutMs,
        maxRetries: config.maxRetries,
      });
    }

    case 'mock':
    default:
      return new MockProvider({ model: config.model || 'mock-provider' });
  }
}
