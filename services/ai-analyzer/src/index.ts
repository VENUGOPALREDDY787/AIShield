import 'dotenv/config';
import { AIContextualAnalyzer } from './analyzer.js';

export * from './types.js';
export * from './analyzer.js';
export * from './schema.js';
export * from './normalizer.js';
export * from './prompts/context-analysis.prompt.js';
export * from './providers/gemini.provider.js';
export * from './providers/openai.provider.js';
export * from './providers/mock.provider.js';
export * from './providers/provider-factory.js';

export const defaultAnalyzer = new AIContextualAnalyzer();
