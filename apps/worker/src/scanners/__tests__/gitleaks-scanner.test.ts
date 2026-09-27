import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { GitleaksScanner } from '../gitleaks-scanner.js';
import type { CommandExecutionOptions, CommandExecutor } from '../types.js';

function loadFixture(filename: string): unknown {
  const fixtureUrl = new URL(`./fixtures/gitleaks/${filename}`, import.meta.url);
  return JSON.parse(fs.readFileSync(fixtureUrl, 'utf-8'));
}

describe('GitleaksScanner', () => {
  describe('Identity and Version', () => {
    it('reports correct scanner identity and caches version', async () => {
      let callCount = 0;
      const mockExecutor: CommandExecutor = async () => {
        callCount++;
        return {
          stdout: 'v8.18.2\n',
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      expect(scanner.getName()).toBe('gitleaks');
      expect(scanner.getDisplayName()).toBe('Gitleaks Secret Scanner');

      const v1 = await scanner.getVersion();
      const v2 = await scanner.getVersion();
      expect(v1).toBe('v8.18.2');
      expect(v2).toBe('v8.18.2');
      expect(callCount).toBe(1); // Cached
    });

    it('probes version via docker when runner is docker', async () => {
      let capturedCommand = '';
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (command, args) => {
        capturedCommand = command;
        capturedArgs = args;
        return { stdout: 'v8.18.2\n', stderr: '', exitCode: 0 };
      };

      const scanner = new GitleaksScanner({
        runner: 'docker',
        dockerImage: 'zricethezav/gitleaks:v8.18.2',
        executor: mockExecutor,
      });

      const version = await scanner.getVersion();
      expect(version).toBe('v8.18.2');
      expect(capturedCommand).toBe('docker');
      expect(capturedArgs).toEqual(['run', '--rm', 'zricethezav/gitleaks:v8.18.2', 'version']);
    });
  });

  describe('Deterministic Normalization and Secret Redaction (Synthetic Secrets)', () => {
    it('normalizes synthetic AWS access key and strictly redacts raw value', async () => {
      const syntheticSecret = 'AKIAIOSFODNN7EXAMPLE';
      const fixtureData = loadFixture('aws-secret.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1, // Gitleaks exits with 1 when leaks are found
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.source).toBe('gitleaks');
      expect(f.ruleId).toBe('aws-access-key-id');
      expect(f.category).toBe('secret');
      expect(f.severity).toBe('critical');
      expect(f.confidence).toBe(0.95);
      expect(f.file).toBe('config/aws.json');
      expect(f.line).toBe(14);
      expect(f.cwe).toBe('CWE-798');
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);

      // SECURITY AUDIT: Verify raw synthetic secret NEVER appears in any user-facing or persisted field
      expect(f.title).not.toContain(syntheticSecret);
      expect(f.description).not.toContain(syntheticSecret);
      expect(f.remediation).not.toContain(syntheticSecret);

      const metadata = f.metadata as { maskedSecret?: string; secretHash?: string };
      expect(metadata.maskedSecret).toBe('AKIA************MPLE');
      expect(metadata.maskedSecret).not.toBe(syntheticSecret);
      expect(metadata.secretHash).toContain('[REDACTED_SHA256:');
      expect(metadata.secretHash).not.toContain(syntheticSecret);

      // Verify rawOutput in envelope is scrubbed
      const raw = result.rawOutput as Array<{ Secret?: string; Match?: string }>;
      expect(raw[0]?.Secret).toBe('AKIA************MPLE');
      expect(raw[0]?.Match).toBe('AKIA************MPLE');
    });

    it('normalizes synthetic GitHub personal access token fixture', async () => {
      const syntheticToken = 'ghp_mocktesttoken000000000000000000000';
      const fixtureData = loadFixture('github-token.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.ruleId).toBe('github-pat');
      expect(f.file).toBe('scripts/deploy.sh');
      expect(f.line).toBe(28);

      const metadata = f.metadata as { maskedSecret?: string; secretHash?: string };
      expect(metadata.maskedSecret).toContain('****');
      expect(metadata.maskedSecret).not.toBe(syntheticToken);
      expect(metadata.secretHash).toMatch(/^\[REDACTED_SHA256:[a-f0-9]{16}\]$/);
    });

    it('normalizes multi-secrets fixture covering varied token types', async () => {
      const fixtureData = loadFixture('multi-secrets.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(3);

      const [aws, slack, generic] = result.findings;
      expect(aws?.ruleId).toBe('aws-access-key-id');
      expect(slack?.ruleId).toBe('slack-bot-token');
      expect(generic?.ruleId).toBe('generic-api-key');

      for (const finding of result.findings) {
        expect(finding.category).toBe('secret');
        expect(finding.severity).toBe('critical');
        expect(finding.cwe).toBe('CWE-798');
        expect((finding.metadata as { maskedSecret?: string }).maskedSecret).toBeDefined();
      }
    });

    it('tolerates clean scan with 0 findings', async () => {
      const fixtureData = loadFixture('clean-scan.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 0,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings).toEqual([]);
    });
  });

  describe('Pull Request Scope and Filtering', () => {
    it('passes commit range via --log-opts when baseCommit and targetCommit are supplied', async () => {
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (_cmd, args) => {
        capturedArgs = args;
        return { stdout: '[]', stderr: '', exitCode: 0 };
      };

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      await scanner.scan({
        targetPath: '/test/repo',
        baseCommit: 'commitA',
        targetCommit: 'commitB',
      });

      expect(capturedArgs).toContain('--log-opts=commitA..commitB');
    });

    it('filters findings to only files modified by the PR when changedFiles is specified', async () => {
      const fixtureData = loadFixture('multi-secrets.json'); // Has findings in storage.ts, slack.ts, database.yml

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({
        targetPath: '/test/repo',
        changedFiles: ['src/services/storage.ts'], // Only 1 file modified in PR
      });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);
      expect(result.findings[0]?.file).toBe('src/services/storage.ts');
      expect(result.findings[0]?.ruleId).toBe('aws-access-key-id');
    });
  });

  describe('Docker Runner Mode', () => {
    it('builds secure docker command with read-only volume, network none, and dropped privileges', async () => {
      let capturedCommand = '';
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (cmd, args) => {
        capturedCommand = cmd;
        capturedArgs = args;
        return { stdout: '[]', stderr: '', exitCode: 0 };
      };

      const scanner = new GitleaksScanner({
        runner: 'docker',
        dockerImage: 'zricethezav/gitleaks:v8.18.2',
        configPath: 'services/gitleaks/gitleaks.toml',
        executor: mockExecutor,
      });

      await scanner.scan({
        targetPath: '/my/repo',
        baseCommit: 'sha1',
        targetCommit: 'sha2',
      });

      expect(capturedCommand).toBe('docker');
      expect(capturedArgs).toContain('run');
      expect(capturedArgs).toContain('--rm');
      expect(capturedArgs).toContain('--network');
      expect(capturedArgs).toContain('none');
      expect(capturedArgs).toContain('--cap-drop=ALL');
      expect(capturedArgs).toContain('--security-opt=no-new-privileges');
      expect(capturedArgs).toContain('-w');
      expect(capturedArgs).toContain('/src');

      // Target volume mount is read-only
      const targetMount = capturedArgs.find((arg) => arg.includes(':/src:ro'));
      expect(targetMount).toBeDefined();

      // Config volume mount
      const configMount = capturedArgs.find((arg) => arg.includes(':/gitleaks.toml:ro'));
      expect(configMount).toBeDefined();

      // Gitleaks flags
      expect(capturedArgs).toContain('detect');
      expect(capturedArgs).toContain('--no-banner');
      expect(capturedArgs).toContain('--report-format=json');
      expect(capturedArgs).toContain('--config=/gitleaks.toml');
      expect(capturedArgs).toContain('--log-opts=sha1..sha2');
      expect(capturedArgs).toContain('--source=/src');
    });

    it('strips container /src/ prefix from file paths', async () => {
      const containerOutput = [
        {
          RuleID: 'aws-access-key-id',
          Description: 'AWS Key',
          File: '/src/config/aws.json',
          StartLine: 10,
          Secret: 'AKIAIOSFODNN7EXAMPLE',
        },
      ];

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(containerOutput),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new GitleaksScanner({ runner: 'docker', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings[0]?.file).toBe('config/aws.json');
    });
  });

  describe('Stable Fingerprinting and PR Comments', () => {
    it('produces stable fingerprints invariant across line movements', async () => {
      const scanner = new GitleaksScanner();

      const findingLine10 = scanner.normalizeResult([
        {
          RuleID: 'aws-access-key-id',
          File: 'config/aws.json',
          StartLine: 10,
          Secret: 'AKIAIOSFODNN7EXAMPLE',
        },
      ])[0]!;

      const findingLine50 = scanner.normalizeResult([
        {
          RuleID: 'aws-access-key-id',
          File: 'config/aws.json',
          StartLine: 50, // Line shifted during code refactor
          Secret: 'AKIAIOSFODNN7EXAMPLE',
        },
      ])[0]!;

      expect(findingLine10.fingerprint).toBe(findingLine50.fingerprint);
    });

    it('formats safe PR comment without revealing raw secret', async () => {
      const rawSecret = 'AKIAIOSFODNN7EXAMPLE';
      const scanner = new GitleaksScanner();
      const findings = scanner.normalizeResult([
        {
          RuleID: 'aws-access-key-id',
          File: 'config/aws.json',
          StartLine: 14,
          Description: 'AWS Access Key',
          Secret: rawSecret,
        },
      ]);

      const comment = scanner.formatPrComment(findings[0]!);

      expect(comment).toContain('### ⚠️ AIShield Security Alert: Hardcoded Secret Detected');
      expect(comment).toContain('`aws-access-key-id`');
      expect(comment).toContain('`config/aws.json:14`');
      expect(comment).toContain('`AKIA************MPLE`');
      expect(comment).toContain('[REDACTED_SHA256:');
      expect(comment).toContain('Immediately Revoke & Rotate');

      // CRITICAL: Raw secret must NOT be in comment markdown
      expect(comment).not.toContain(rawSecret);
    });
  });

  describe('Resilience and Error Handling', () => {
    it('handles Gitleaks not installed (ENOENT) gracefully', async () => {
      const mockExecutor: CommandExecutor = async () => {
        const error = new Error('spawn gitleaks ENOENT') as Error & { code?: string };
        error.code = 'ENOENT';
        throw error;
      };

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain("Scanner executable 'gitleaks' is not installed or not found in PATH");
    });

    it('handles scanner timeout gracefully', async () => {
      const mockExecutor: CommandExecutor = async (_cmd, _args, options: CommandExecutionOptions) => {
        return new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(new Error('Command timed out or aborted: gitleaks'));
          });
        });
      };

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo', timeoutMs: 20 });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('timed out or aborted');
    });

    it('handles invalid repository path gracefully when validation is enabled', async () => {
      const scanner = new GitleaksScanner();
      const result = await scanner.scan({
        targetPath: '/non/existent/path/999999',
        validateTargetPath: true,
      });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Target repository path does not exist or is not accessible');
    });

    it('handles malformed JSON output without crashing', async () => {
      const mockExecutor: CommandExecutor = async () => ({
        stdout: 'not valid json at all',
        stderr: '',
        exitCode: 0,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Failed to parse scanner output as JSON');
    });

    it('handles process failure with exit code >= 2', async () => {
      const mockExecutor: CommandExecutor = async () => ({
        stdout: '',
        stderr: 'fatal: ambiguous argument: unknown revision',
        exitCode: 2,
      });

      const scanner = new GitleaksScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Scanner process failed with exit code 2');
      expect(result.error).toContain('ambiguous argument');
    });
  });
});
