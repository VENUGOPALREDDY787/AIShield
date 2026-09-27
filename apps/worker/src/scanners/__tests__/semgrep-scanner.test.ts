import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SemgrepScanner } from '../semgrep-scanner.js';
import type { CommandExecutionOptions, CommandExecutor } from '../types.js';

function loadFixture(filename: string): unknown {
  const fixtureUrl = new URL(`./fixtures/semgrep/${filename}`, import.meta.url);
  return JSON.parse(fs.readFileSync(fixtureUrl, 'utf-8'));
}

describe('SemgrepScanner', () => {
  describe('Identity and Version', () => {
    it('reports correct scanner identity and caches version', async () => {
      let callCount = 0;
      const mockExecutor: CommandExecutor = async () => {
        callCount++;
        return {
          stdout: '1.78.0\n',
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      expect(scanner.getName()).toBe('semgrep');
      expect(scanner.getDisplayName()).toBe('Semgrep SAST Scanner');

      const version1 = await scanner.getVersion();
      const version2 = await scanner.getVersion();
      expect(version1).toBe('1.78.0');
      expect(version2).toBe('1.78.0');
      expect(callCount).toBe(1); // Cached after first call
    });

    it('probes version via docker when runner is docker', async () => {
      let executedCommand = '';
      let executedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (command, args) => {
        executedCommand = command;
        executedArgs = args;
        return { stdout: '1.78.0\n', stderr: '', exitCode: 0 };
      };

      const scanner = new SemgrepScanner({
        runner: 'docker',
        dockerImage: 'returntocorp/semgrep:1.78.0',
        executor: mockExecutor,
      });

      const version = await scanner.getVersion();
      expect(version).toBe('1.78.0');
      expect(executedCommand).toBe('docker');
      expect(executedArgs).toEqual(['run', '--rm', 'returntocorp/semgrep:1.78.0', 'semgrep', '--version']);
    });
  });

  describe('Deterministic Normalization from Fixtures', () => {
    it('normalizes SQL injection finding (CWE-89) from fixture into critical severity', async () => {
      const fixtureData = loadFixture('sql-injection.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1, // Semgrep exits with 1 when findings exist
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.source).toBe('semgrep');
      expect(f.ruleId).toBe('javascript.lang.security.audit.sqli.node-postgres-sqli');
      expect(f.category).toBe('security');
      expect(f.title).toBe('Detected string concatenation in SQL query. This can lead to SQL injection vulnerabilities.');
      expect(f.description).toContain('Detected string concatenation in SQL query');
      expect(f.severity).toBe('critical'); // High impact SQL injection mapped to critical
      expect(f.confidence).toBe(0.95);
      expect(f.file).toBe('src/controllers/users.js');
      expect(f.line).toBe(42);
      expect(f.endLine).toBe(45);
      expect(f.cwe).toBe('CWE-89');
      expect(f.remediation).toBe("await client.query('SELECT * FROM users WHERE id = $1', [req.query.id]);");
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/); // SHA-256

      // Metadata preservation
      expect(f.metadata.owasp).toEqual(['A03:2021 - Injection']);
      expect(f.metadata.rawSeverity).toBe('ERROR');
      expect(f.metadata.impact).toBe('HIGH');
      expect(f.metadata.shortlink).toBe('https://sg.run/sql-inject-node');
    });

    it('normalizes eval injection finding (CWE-95) from fixture', async () => {
      const fixtureData = loadFixture('eval-injection.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.ruleId).toBe('javascript.lang.security.audit.eval.eval-with-expression');
      expect(f.severity).toBe('critical');
      expect(f.cwe).toBe('CWE-95');
      expect(f.file).toBe('src/utils/dynamic-calculator.ts');
      expect(f.line).toBe(18);
      expect(f.remediation).toBe('const result = safeMathParser.evaluate(userFormula);');
    });

    it('normalizes multi-findings fixture covering security, secret, and debt categories', async () => {
      const fixtureData = loadFixture('multi-findings.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(4);

      const [sqli, cors, debt, secret] = result.findings;

      // SQLi
      expect(sqli?.ruleId).toBe('javascript.express.security.audit.sqli.raw-query');
      expect(sqli?.severity).toBe('critical');
      expect(sqli?.category).toBe('security');
      expect(sqli?.cwe).toBe('CWE-89');

      // CORS
      expect(cors?.ruleId).toBe('javascript.express.security.audit.permissive-cors');
      expect(cors?.severity).toBe('medium');
      expect(cors?.cwe).toBe('CWE-942');

      // Maintainability debt
      expect(debt?.ruleId).toBe('generic.maintainability.audit.high-cyclomatic-complexity');
      expect(debt?.category).toBe('debt');
      expect(debt?.severity).toBe('low');

      // Hardcoded Secret
      expect(secret?.ruleId).toBe('generic.secrets.security.audit.hardcoded-jwt-secret');
      expect(secret?.category).toBe('secret');
      expect(secret?.severity).toBe('critical');
      expect(secret?.cwe).toBe('CWE-798');
    });

    it('handles clean scan with 0 findings gracefully', async () => {
      const fixtureData = loadFixture('clean-scan.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 0,
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings).toEqual([]);
      expect(result.rawOutput).toBeDefined();
    });
  });

  describe('Command Construction and Runner Execution', () => {
    it('builds secure docker command with read-only volume, network isolation, and dropped capabilities', async () => {
      let capturedCommand = '';
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (command, args) => {
        capturedCommand = command;
        capturedArgs = args;
        return {
          stdout: JSON.stringify({ results: [], errors: [] }),
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new SemgrepScanner({
        runner: 'docker',
        dockerImage: 'returntocorp/semgrep:1.78.0',
        rules: ['p/security-audit', 'p/owasp-top-ten'],
        dockerNetwork: 'none',
        executor: mockExecutor,
      });

      await scanner.scan({ targetPath: '/mock/workspace' });

      expect(capturedCommand).toBe('docker');
      expect(capturedArgs).toContain('run');
      expect(capturedArgs).toContain('--rm');
      expect(capturedArgs).toContain('--network');
      expect(capturedArgs).toContain('none');
      expect(capturedArgs).toContain('--cap-drop=ALL');
      expect(capturedArgs).toContain('--security-opt=no-new-privileges');
      expect(capturedArgs).toContain('-w');
      expect(capturedArgs).toContain('/src');

      // Check read-only mount
      const volumeArgIndex = capturedArgs.indexOf('-v');
      expect(volumeArgIndex).toBeGreaterThan(-1);
      expect(capturedArgs[volumeArgIndex + 1]).toContain(':/src:ro');

      // Check image and subcommands
      expect(capturedArgs).toContain('returntocorp/semgrep:1.78.0');
      expect(capturedArgs).toContain('semgrep');
      expect(capturedArgs).toContain('scan');
      expect(capturedArgs).toContain('--json');
      expect(capturedArgs).toContain('--metrics=off');
      expect(capturedArgs).toContain('--disable-version-check');

      // Check rules
      expect(capturedArgs).toContain('p/security-audit');
      expect(capturedArgs).toContain('p/owasp-top-ten');
      expect(capturedArgs).toContain('/src');
    });

    it('strips container /src/ prefix from findings in Docker runner mode', async () => {
      const containerOutput = {
        results: [
          {
            check_id: 'docker.test.rule',
            path: '/src/services/api/index.ts',
            start: { line: 10 },
            extra: { message: 'Docker finding' },
          },
        ],
      };

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(containerOutput),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new SemgrepScanner({ runner: 'docker', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/mock/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings[0]?.file).toBe('services/api/index.ts');
    });

    it('filters scan to PR changed files via --include flags', async () => {
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (_cmd, args) => {
        capturedArgs = args;
        return {
          stdout: JSON.stringify({ results: [], errors: [] }),
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      await scanner.scan({
        targetPath: '/test/repo',
        changedFiles: ['src/auth/jwt.ts', 'src/controllers/auth.ts'],
      });

      // Verify --include flags
      const includeIndices = capturedArgs.reduce<number[]>((acc, arg, i) => {
        if (arg === '--include') acc.push(i);
        return acc;
      }, []);

      expect(includeIndices.length).toBe(2);
      expect(capturedArgs[includeIndices[0]! + 1]).toBe('src/auth/jwt.ts');
      expect(capturedArgs[includeIndices[1]! + 1]).toBe('src/controllers/auth.ts');
    });

    it('supports custom rule paths and configurations', async () => {
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (_cmd, args) => {
        capturedArgs = args;
        return {
          stdout: JSON.stringify({ results: [], errors: [] }),
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new SemgrepScanner({
        runner: 'local',
        rules: ['p/cwe-top-25'],
        customRulePaths: ['services/semgrep/rules/security-debt.yml'],
        executor: mockExecutor,
      });

      await scanner.scan({ targetPath: '/test/repo' });

      expect(capturedArgs).toContain('p/cwe-top-25');
      expect(capturedArgs).toContain('services/semgrep/rules/security-debt.yml');
    });
  });

  describe('Resilience and Error Handling', () => {
    it('handles Semgrep not installed (ENOENT) gracefully', async () => {
      const mockExecutor: CommandExecutor = async () => {
        const error = new Error('spawn semgrep ENOENT') as Error & { code?: string };
        error.code = 'ENOENT';
        throw error;
      };

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain("Scanner executable 'semgrep' is not installed or not found in PATH");
    });

    it('handles scan execution timeout gracefully', async () => {
      const mockExecutor: CommandExecutor = async (_cmd, _args, options: CommandExecutionOptions) => {
        return new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(new Error(`Command timed out or aborted: semgrep`));
          });
        });
      };

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo', timeoutMs: 20 });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('timed out or aborted');
    });

    it('handles invalid repository path gracefully when validation is enabled', async () => {
      const scanner = new SemgrepScanner();
      const result = await scanner.scan({
        targetPath: '/path/that/definitely/does/not/exist/99999',
        validateTargetPath: true,
      });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Target repository path does not exist or is not accessible');
    });

    it('handles malformed JSON output without crashing', async () => {
      const mockExecutor: CommandExecutor = async () => ({
        stdout: '{ malformed json: true, unclosed bracket',
        stderr: 'Warning: incomplete stream',
        exitCode: 0,
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Failed to parse scanner output as JSON');
    });

    it('handles scanner process failure with exit code >= 2', async () => {
      const mockExecutor: CommandExecutor = async () => ({
        stdout: '',
        stderr: 'semgrep: error: unrecognized argument: --invalid-flag',
        exitCode: 2,
      });

      const scanner = new SemgrepScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Scanner process failed with exit code 2');
      expect(result.error).toContain('unrecognized argument');
    });
  });
});
