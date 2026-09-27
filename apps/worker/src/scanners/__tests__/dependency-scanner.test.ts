import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DependencyScanner } from '../dependency-scanner.js';
import type { CommandExecutionOptions, CommandExecutor } from '../types.js';

function loadFixture(filename: string): unknown {
  const fixtureUrl = new URL(`./fixtures/osv/${filename}`, import.meta.url);
  return JSON.parse(fs.readFileSync(fixtureUrl, 'utf-8'));
}

describe('DependencyScanner', () => {
  describe('Identity and Version', () => {
    it('reports correct scanner identity and caches version', async () => {
      let callCount = 0;
      const mockExecutor: CommandExecutor = async () => {
        callCount++;
        return {
          stdout: 'osv-scanner version: 1.7.0\n',
          stderr: '',
          exitCode: 0,
        };
      };

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      expect(scanner.getName()).toBe('dependency');
      expect(scanner.getDisplayName()).toBe('OSV Dependency Vulnerability Scanner');

      const v1 = await scanner.getVersion();
      const v2 = await scanner.getVersion();
      expect(v1).toContain('1.7.0');
      expect(v2).toContain('1.7.0');
      expect(callCount).toBe(1); // Cached
    });

    it('probes version via docker when runner is docker', async () => {
      let capturedCommand = '';
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (cmd, args) => {
        capturedCommand = cmd;
        capturedArgs = args;
        return { stdout: 'osv-scanner version: 1.7.0\n', stderr: '', exitCode: 0 };
      };

      const scanner = new DependencyScanner({
        runner: 'docker',
        dockerImage: 'ghcr.io/google/osv-scanner:v1.7.0',
        executor: mockExecutor,
      });

      const version = await scanner.getVersion();
      expect(version).toContain('1.7.0');
      expect(capturedCommand).toBe('docker');
      expect(capturedArgs).toEqual(['run', '--rm', 'ghcr.io/google/osv-scanner:v1.7.0', '--version']);
    });
  });

  describe('Node.js Dependency Vulnerability Analysis', () => {
    it('normalizes npm vulnerability fixture capturing CVE, GHSA, CWE, and fix version', async () => {
      const fixtureData = loadFixture('npm-vuln.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1, // OSV exits with 1 when vulnerabilities are present
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.source).toBe('dependency');
      expect(f.ruleId).toBe('GHSA-35jh-r3h4-6jhm');
      expect(f.category).toBe('dependency');
      expect(f.title).toBe('lodash@4.17.20: Command Injection in lodash');
      expect(f.description).toContain('Command Injection');
      expect(f.severity).toBe('high');
      expect(f.confidence).toBe(1.0);
      expect(f.file).toBe('package-lock.json');
      expect(f.line).toBe(1);
      expect(f.cwe).toBe('CWE-78');
      expect(f.remediation).toBe('Upgrade lodash to version 4.17.21 or higher.');
      expect(f.fingerprint).toMatch(/^[a-f0-9]{64}$/);

      const meta = f.metadata as {
        packageName?: string;
        installedVersion?: string;
        fixedVersion?: string;
        ecosystem?: string;
        cve?: string;
        ghsa?: string;
      };
      expect(meta.packageName).toBe('lodash');
      expect(meta.installedVersion).toBe('4.17.20');
      expect(meta.fixedVersion).toBe('4.17.21');
      expect(meta.ecosystem).toBe('npm');
      expect(meta.cve).toBe('CVE-2021-23337');
      expect(meta.ghsa).toBe('GHSA-35jh-r3h4-6jhm');
    });
  });

  describe('Extensibility for Other Ecosystems (Python and Java)', () => {
    it('normalizes Python PyPI vulnerability (requirements.txt)', async () => {
      const fixtureData = loadFixture('python-vuln.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.file).toBe('requirements.txt');
      expect(f.title).toBe('urllib3@1.25.8: CRLF Injection in urllib3');
      expect(f.severity).toBe('medium');
      expect(f.cwe).toBe('CWE-93');
      expect(f.remediation).toBe('Upgrade urllib3 to version 1.25.9 or higher.');

      const meta = f.metadata as { ecosystem?: string; packageName?: string; cve?: string };
      expect(meta.ecosystem).toBe('PyPI');
      expect(meta.packageName).toBe('urllib3');
      expect(meta.cve).toBe('CVE-2020-26137');
    });

    it('normalizes Java Maven vulnerability (pom.xml Log4Shell as critical)', async () => {
      const fixtureData = loadFixture('java-vuln.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(1);

      const f = result.findings[0]!;
      expect(f.file).toBe('pom.xml');
      expect(f.severity).toBe('critical'); // Log4Shell is critical
      expect(f.cwe).toBe('CWE-502');
      expect(f.remediation).toBe('Upgrade org.apache.logging.log4j:log4j-core to version 2.15.0 or higher.');

      const meta = f.metadata as { ecosystem?: string; packageName?: string; cve?: string; ghsa?: string };
      expect(meta.ecosystem).toBe('Maven');
      expect(meta.packageName).toBe('org.apache.logging.log4j:log4j-core');
      expect(meta.cve).toBe('CVE-2021-44228');
      expect(meta.ghsa).toBe('GHSA-jfh8-c2jp-5v3q');
    });

    it('normalizes multiple vulnerabilities with varied severities', async () => {
      const fixtureData = loadFixture('multi-vulns.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings.length).toBe(3);

      const [criticalVuln, modVuln, lowVuln] = result.findings;
      expect(criticalVuln?.severity).toBe('critical');
      expect(criticalVuln?.ruleId).toBe('GHSA-qwph-4952-7xr6');
      expect(criticalVuln?.title).toContain('jsonwebtoken');

      expect(modVuln?.severity).toBe('medium');
      expect(modVuln?.ruleId).toBe('GHSA-c2qf-rxjj-qqgw');
      expect(modVuln?.title).toContain('semver');

      expect(lowVuln?.severity).toBe('low');
      expect(lowVuln?.ruleId).toBe('GHSA-xvch-5ox4-994e');
      expect(lowVuln?.title).toContain('minimist');
    });

    it('handles clean scan with 0 vulnerabilities gracefully', async () => {
      const fixtureData = loadFixture('clean-scan.json');

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(fixtureData),
        stderr: '',
        exitCode: 0,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings).toEqual([]);
    });
  });

  describe('Pull Request Scope and Lockfile Targeting', () => {
    it('targets specific lockfiles when PR changed files contain a package manifest', async () => {
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (_cmd, args) => {
        capturedArgs = args;
        return { stdout: '{"results": []}', stderr: '', exitCode: 0 };
      };

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      await scanner.scan({
        targetPath: '/test/repo',
        changedFiles: ['src/index.ts', 'package-lock.json'],
      });

      expect(capturedArgs).toContain('--lockfile=package-lock.json');
      expect(capturedArgs).not.toContain('-r');
    });

    it('scans recursively when PR changes contain no lockfiles', async () => {
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (_cmd, args) => {
        capturedArgs = args;
        return { stdout: '{"results": []}', stderr: '', exitCode: 0 };
      };

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      await scanner.scan({
        targetPath: '/test/repo',
        changedFiles: ['src/auth/jwt.ts', 'README.md'],
      });

      expect(capturedArgs).toContain('-r');
      expect(capturedArgs).toContain('/test/repo');
    });
  });

  describe('Docker Runner Mode', () => {
    it('builds secure docker command with read-only volume and bridge network', async () => {
      let capturedCommand = '';
      let capturedArgs: string[] = [];

      const mockExecutor: CommandExecutor = async (cmd, args) => {
        capturedCommand = cmd;
        capturedArgs = args;
        return { stdout: '{"results": []}', stderr: '', exitCode: 0 };
      };

      const scanner = new DependencyScanner({
        runner: 'docker',
        dockerImage: 'ghcr.io/google/osv-scanner:v1.7.0',
        executor: mockExecutor,
      });

      await scanner.scan({ targetPath: '/workspace/project' });

      expect(capturedCommand).toBe('docker');
      expect(capturedArgs).toContain('run');
      expect(capturedArgs).toContain('--rm');
      expect(capturedArgs).toContain('--network');
      expect(capturedArgs).toContain('bridge');
      expect(capturedArgs).toContain('--cap-drop=ALL');
      expect(capturedArgs).toContain('--security-opt=no-new-privileges');
      expect(capturedArgs).toContain('-w');
      expect(capturedArgs).toContain('/src');

      const volumeArg = capturedArgs.find((a) => a.includes(':/src:ro'));
      expect(volumeArg).toBeDefined();

      expect(capturedArgs).toContain('ghcr.io/google/osv-scanner:v1.7.0');
      expect(capturedArgs).toContain('--json');
      expect(capturedArgs).toContain('-r');
      expect(capturedArgs).toContain('/src');
    });

    it('strips container /src/ prefix from manifest paths', async () => {
      const containerOutput = {
        results: [
          {
            source: { path: '/src/package-lock.json', type: 'lockfile' },
            packages: [
              {
                package: { name: 'debug', version: '2.6.8', ecosystem: 'npm' },
                vulnerabilities: [
                  {
                    id: 'GHSA-gxpj-cx7g-858c',
                    summary: 'ReDoS in debug',
                  },
                ],
              },
            ],
          },
        ],
      };

      const mockExecutor: CommandExecutor = async () => ({
        stdout: JSON.stringify(containerOutput),
        stderr: '',
        exitCode: 1,
      });

      const scanner = new DependencyScanner({ runner: 'docker', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('succeeded');
      expect(result.findings[0]?.file).toBe('package-lock.json');
    });
  });

  describe('Stable Fingerprinting', () => {
    it('generates reproducible, stable fingerprints for dependency findings', async () => {
      const scanner = new DependencyScanner();
      const mockResult = {
        results: [
          {
            source: { path: 'package-lock.json' },
            packages: [
              {
                package: { name: 'axios', version: '0.21.1', ecosystem: 'npm' },
                vulnerabilities: [{ id: 'GHSA-cph5-m8f7-6c5x', summary: 'SSRF in axios' }],
              },
            ],
          },
        ],
      };

      const findings1 = scanner.normalizeResult(mockResult);
      const findings2 = scanner.normalizeResult(mockResult);

      expect(findings1[0]?.fingerprint).toBe(findings2[0]?.fingerprint);
      expect(findings1[0]?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('Resilience and Error Handling', () => {
    it('handles osv-scanner not installed (ENOENT) gracefully', async () => {
      const mockExecutor: CommandExecutor = async () => {
        const error = new Error('spawn osv-scanner ENOENT') as Error & { code?: string };
        error.code = 'ENOENT';
        throw error;
      };

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain("Scanner executable 'dependency' is not installed or not found in PATH");
    });

    it('handles scanner timeout gracefully', async () => {
      const mockExecutor: CommandExecutor = async (_cmd, _args, options: CommandExecutionOptions) => {
        return new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(new Error('Command timed out or aborted: osv-scanner'));
          });
        });
      };

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo', timeoutMs: 20 });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('timed out or aborted');
    });

    it('handles invalid repository path gracefully when validation is enabled', async () => {
      const scanner = new DependencyScanner();
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
        stdout: 'not valid json',
        stderr: '',
        exitCode: 0,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Failed to parse scanner output as JSON');
    });

    it('handles process failure with exit code >= 2', async () => {
      const mockExecutor: CommandExecutor = async () => ({
        stdout: '',
        stderr: 'osv-scanner: failed to connect to osv.dev API',
        exitCode: 2,
      });

      const scanner = new DependencyScanner({ runner: 'local', executor: mockExecutor });
      const result = await scanner.scan({ targetPath: '/test/repo' });

      expect(result.status).toBe('failed');
      expect(result.findings).toEqual([]);
      expect(result.error).toContain('Scanner process failed with exit code 2');
      expect(result.error).toContain('failed to connect to osv.dev API');
    });
  });
});
