import type { LLMProvider, LLMRequestOptions } from '../types.js';

export interface MockProviderConfig {
  readonly model?: string;
  readonly mockResponse?: string;
  readonly delayMs?: number;
  readonly shouldFail?: boolean;
  readonly failureError?: Error;
}

export class MockProvider implements LLMProvider {
  readonly name = 'mock';
  readonly model: string;
  private mockResponse: string;
  private delayMs: number;
  private shouldFail: boolean;
  private failureError?: Error;

  constructor(config: MockProviderConfig = {}) {
    this.model = config.model || 'mock-security-llm';
    this.delayMs = config.delayMs ?? 0;
    this.shouldFail = config.shouldFail ?? false;
    this.failureError = config.failureError;
    this.mockResponse =
      config.mockResponse ||
      JSON.stringify({
        findings: [
          {
            category: 'security',
            title: 'Missing Authorization Check on Profile Update Endpoint',
            description:
              'The PUT /api/users/:id endpoint updates user profiles without checking if the authenticated user owns the ID or possesses admin role (IDOR vulnerability).',
            severity: 'high',
            confidence: 0.9,
            file: 'src/controllers/user.controller.ts',
            line: 45,
            evidence: 'await db.users.update({ where: { id: req.params.id }, data: req.body });',
            remediation:
              'Verify req.user.id === req.params.id or enforce role-based authorization middleware before applying changes.',
            reasoning_summary:
              'The route handler accepts an arbitrary user ID from request parameters without comparing it against the authenticated session token, enabling any authenticated user to modify another users profile data.',
          },
        ],
      });
  }

  setMockResponse(response: string): void {
    this.mockResponse = response;
  }

  setShouldFail(shouldFail: boolean, error?: Error): void {
    this.shouldFail = shouldFail;
    this.failureError = error;
  }

  async generateText(
    _systemPrompt: string,
    _userPrompt: string,
    options: LLMRequestOptions = {},
  ): Promise<string> {
    if (this.delayMs > 0) {
      await new Promise((r) => setTimeout(r, this.delayMs));
    }

    if (options.signal?.aborted) {
      throw new Error('Command timed out or aborted');
    }

    if (this.shouldFail) {
      throw this.failureError || new Error('Mock LLM provider simulated failure');
    }

    return this.mockResponse;
  }
}
