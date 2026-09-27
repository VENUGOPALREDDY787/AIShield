import { describe, expect, it } from 'vitest';
import { AIContextualAnalyzer } from '../analyzer.js';
import { normalizeAIFindings } from '../normalizer.js';
import { SYSTEM_SECURITY_ANALYST_PROMPT, buildUserPrompt } from '../prompts/context-analysis.prompt.js';
import { MockProvider } from '../providers/mock.provider.js';
import { extractAndParseJson, validateAIOutput } from '../schema.js';
import type { AIFinding } from '../types.js';

describe('AI Contextual Security Analyzer', () => {
  describe('Zod Schema Validation & Extraction', () => {
    it('validates strictly conforming structured JSON output', () => {
      const validPayload = {
        findings: [
          {
            category: 'security',
            title: 'Missing Authorization Check on Profile Update',
            description: 'The endpoint updates records without verifying ownership.',
            severity: 'high',
            confidence: 0.9,
            file: 'src/controllers/user.ts',
            line: 42,
            evidence: 'await db.users.update({ where: { id: req.params.id } });',
            remediation: 'Verify req.user.id matches req.params.id before updating.',
            reasoning_summary: 'Parameter ID is directly trusted without session validation.',
          },
        ],
      };

      const result = validateAIOutput(validPayload);
      expect(result.findings.length).toBe(1);
      expect(result.findings[0]?.title).toBe('Missing Authorization Check on Profile Update');
      expect(result.findings[0]?.severity).toBe('high');
    });

    it('strips Markdown code fences and parses JSON cleanly', () => {
      const markdownJson = [
        '```json',
        '{',
        '  "findings": [',
        '    {',
        '      "category": "security",',
        '      "title": "Insecure Direct Object Reference (IDOR)",',
        '      "description": "User can delete any document.",',
        '      "severity": "critical",',
        '      "confidence": 0.95,',
        '      "file": "src/api/docs.ts",',
        '      "line": 15,',
        '      "evidence": "db.docs.delete(req.params.id)",',
        '      "remediation": "Check doc.ownerId === req.user.id",',
        '      "reasoning_summary": "No tenancy or ownership check."',
        '    }',
        '  ]',
        '}',
        '```',
      ].join('\n');

      const parsed = extractAndParseJson(markdownJson);
      const validated = validateAIOutput(parsed);
      expect(validated.findings.length).toBe(1);
      expect(validated.findings[0]?.severity).toBe('critical');
    });

    it('rejects malformed non-JSON responses', () => {
      expect(() => extractAndParseJson('I analyzed the code and found no bugs.')).toThrow(
        /does not contain a valid JSON object structure/,
      );
    });

    it('rejects responses missing mandatory fields like remediation or reasoning_summary', () => {
      const invalidPayload = {
        findings: [
          {
            category: 'security',
            title: 'Missing Auth',
            description: 'No auth check',
            severity: 'high',
            confidence: 0.9,
            file: 'src/api.ts',
            line: 10,
            evidence: 'code snippet',
            // Missing remediation and reasoning_summary
          },
        ],
      };

      expect(() => validateAIOutput(invalidPayload)).toThrow(/LLM output failed schema validation/);
    });

    it('rejects invalid enum values for severity or category', () => {
      const invalidPayload = {
        findings: [
          {
            category: 'unrecognized_category',
            title: 'Invalid finding',
            description: 'Description',
            severity: 'catastrophic', // Invalid severity
            confidence: 0.8,
            file: 'src/index.ts',
            line: 1,
            evidence: 'ev',
            remediation: 'rem',
            reasoning_summary: 'justification',
          },
        ],
      };

      expect(() => validateAIOutput(invalidPayload)).toThrow(/LLM output failed schema validation/);
    });
  });

  describe('Prompt Construction, Minimization & Secret Redaction', () => {
    it('instructs model not to use chain-of-thought and to provide concise reasoning', () => {
      expect(SYSTEM_SECURITY_ANALYST_PROMPT).toContain('Do NOT output chain-of-thought');
      expect(SYSTEM_SECURITY_ANALYST_PROMPT).toContain('reasoning_summary');
      expect(SYSTEM_SECURITY_ANALYST_PROMPT).toContain('inert text data');
    });

    it('redacts sensitive values from diff before constructing prompt', () => {
      const rawDiff = [
        'diff --git a/config.ts b/config.ts',
        '+ const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
        '+ const DB_PASSWORD = "super_secret_db_password_12345";',
        '+ const token = "ghp_mocktesttoken000000000000000000000";',
      ].join('\n');

      const prompt = buildUserPrompt({
        scanId: 'scan-123',
        diffContent: rawDiff,
        repositoryContext: { language: 'TypeScript', framework: 'Express' },
      });

      // Secrets must be redacted from prompt body
      expect(prompt).not.toContain('AKIAIOSFODNN7EXAMPLE');
      expect(prompt).not.toContain('ghp_mocktesttoken000000000000000000000');
      expect(prompt).toContain('[REDACTED]');
      expect(prompt).toContain('### Repository Context');
      expect(prompt).toContain('- Language: TypeScript');
      expect(prompt).toContain('- Framework: Express');
    });

    it('truncates oversized diffs beyond maximum lines limit', () => {
      const massiveDiff = Array.from({ length: 2500 }, (_, i) => `+ line ${i} of code`).join('\n');
      const prompt = buildUserPrompt({
        scanId: 'scan-456',
        diffContent: massiveDiff,
        maxDiffLines: 100,
      });

      expect(prompt).toContain('lines omitted for context minimization');
      expect(prompt.split('\n').length).toBeLessThan(200);
    });

    it('summarizes existing deterministic findings to prevent duplicate reporting', () => {
      const prompt = buildUserPrompt({
        scanId: 'scan-789',
        diffContent: '+ const x = 1;',
        deterministicFindings: [
          {
            source: 'semgrep',
            ruleId: 'javascript.lang.security.audit.sqli',
            category: 'security',
            title: 'SQL Injection in users query',
            description: 'Concatenation detected',
            severity: 'critical',
            confidence: 0.95,
            file: 'src/users.ts',
            line: 42,
            fingerprint: 'fp-1',
            metadata: {},
          },
        ],
      });

      expect(prompt).toContain('### Existing Deterministic Findings');
      expect(prompt).toContain('[SEMGREP] SQL Injection in users query (src/users.ts:42, Severity: critical)');
      expect(prompt).toContain('Do NOT duplicate these findings');
    });
  });

  describe('Analyzer Execution with Mock Provider', () => {
    it('analyzes contextual authorization gap and returns validated findings', async () => {
      const mockFinding: AIFinding = {
        category: 'security',
        title: 'Missing Authorization Check in Document Deletion',
        description: 'DELETE /api/documents/:id does not verify user ownership before calling delete().',
        severity: 'high',
        confidence: 0.9,
        file: 'src/controllers/documents.ts',
        line: 88,
        evidence: 'await Document.deleteOne({ _id: req.params.id });',
        remediation: 'Ensure query filter includes { _id: req.params.id, ownerId: req.user.id }.',
        reasoning_summary:
          'Any authenticated user can delete documents belonging to other users by specifying the document ID.',
      };

      const mockProvider = new MockProvider({
        mockResponse: JSON.stringify({ findings: [mockFinding] }),
      });

      const analyzer = new AIContextualAnalyzer(mockProvider);
      const response = await analyzer.analyze({
        scanId: 'scan-1',
        diffContent: 'diff --git a/src/controllers/documents.ts ...',
      });

      expect(response.status).toBe('succeeded');
      expect(response.findings.length).toBe(1);

      const f = response.findings[0]!;
      expect(f.title).toBe('Missing Authorization Check in Document Deletion');
      expect(f.severity).toBe('high');
      expect(f.evidence).toContain('Document.deleteOne');
      expect(f.reasoning_summary).toContain('belonging to other users');
    });

    it('returns empty findings cleanly when code diff is empty without calling LLM', async () => {
      let providerCalled = false;
      const mockProvider = new MockProvider();
      const origGenerate = mockProvider.generateText.bind(mockProvider);
      mockProvider.generateText = async (...args) => {
        providerCalled = true;
        return origGenerate(...args);
      };

      const analyzer = new AIContextualAnalyzer(mockProvider);
      const response = await analyzer.analyze({
        scanId: 'scan-empty',
        diffContent: '   ',
      });

      expect(response.status).toBe('succeeded');
      expect(response.findings).toEqual([]);
      expect(providerCalled).toBe(false); // Short-circuited safely
    });

    it('handles LLM provider failure gracefully without throwing unhandled exceptions', async () => {
      const mockProvider = new MockProvider({
        shouldFail: true,
        failureError: new Error('Rate limit exceeded (HTTP 429)'),
      });

      const analyzer = new AIContextualAnalyzer(mockProvider);
      const response = await analyzer.analyze({
        scanId: 'scan-fail',
        diffContent: '+ const a = 1;',
      });

      expect(response.status).toBe('failed');
      expect(response.findings).toEqual([]);
      expect(response.error).toContain('Rate limit exceeded');
    });

    it('rejects and reports failure envelope when LLM returns invalid JSON schema', async () => {
      const mockProvider = new MockProvider({
        mockResponse: '{"findings": [{"title": "Missing all other fields"}]}',
      });

      const analyzer = new AIContextualAnalyzer(mockProvider);
      const response = await analyzer.analyze({
        scanId: 'scan-schema-error',
        diffContent: '+ const a = 1;',
      });

      expect(response.status).toBe('failed');
      expect(response.findings).toEqual([]);
      expect(response.error).toContain('schema validation');
    });

    it('normalizes AI findings into standard NormalizedFinding objects', async () => {
      const mockFinding: AIFinding = {
        category: 'debt',
        title: 'Risky Assumption: Unvalidated Third-Party Webhook Signature',
        description: 'Webhook payload is parsed and trusted without HMAC verification.',
        severity: 'medium',
        confidence: 0.85,
        file: 'src/webhooks/stripe.ts',
        line: 25,
        evidence: 'const event = req.body;',
        remediation: 'Use stripe.webhooks.constructEvent(req.rawBody, sig, secret).',
        reasoning_summary: 'Allows unauthenticated attackers to forge billing webhook events.',
      };

      const mockProvider = new MockProvider({
        mockResponse: JSON.stringify({ findings: [mockFinding] }),
      });

      const analyzer = new AIContextualAnalyzer(mockProvider);
      const res = await analyzer.analyzeAndNormalize({
        scanId: 'scan-norm',
        diffContent: '+ const event = req.body;',
      });

      expect(res.status).toBe('succeeded');
      expect(res.findings.length).toBe(1);

      const f = res.findings[0]!;
      expect(f.source).toBe('ai-analyzer');
      expect(f.ruleId).toBe('ai-contextual-risky-assumption-unvalidated-third-party-webhook-signature');
      expect(f.category).toBe('debt');
      expect(f.severity).toBe('medium');
      expect(f.confidence).toBe(0.85);
      expect(f.file).toBe('src/webhooks/stripe.ts');
      expect(f.line).toBe(25);
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);
      expect(f.remediation).toContain('stripe.webhooks.constructEvent');
      expect(f.metadata.evidence).toBe('const event = req.body;');
      expect(f.metadata.reasoningSummary).toContain('forge billing webhook events');
    });
  });

  describe('Finding Normalizer', () => {
    it('generates consistent fingerprints for the same AI finding', () => {
      const finding: AIFinding = {
        category: 'security',
        title: 'IDOR in Invoice Endpoint',
        description: 'No ownership check',
        severity: 'high',
        confidence: 0.9,
        file: '/src/invoices.ts',
        line: 30,
        evidence: 'db.invoices.find(req.params.id)',
        remediation: 'Check owner',
        reasoning_summary: 'Direct param lookup',
      };

      const [n1] = normalizeAIFindings([finding], { model: 'mock', provider: 'mock' });
      const [n2] = normalizeAIFindings([finding], { model: 'mock', provider: 'mock' });

      expect(n1?.file).toBe('invoices.ts'); // Stripped /src/
      expect(n1?.fingerprint).toBe(n2?.fingerprint);
      expect(n1?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });
  });
});
