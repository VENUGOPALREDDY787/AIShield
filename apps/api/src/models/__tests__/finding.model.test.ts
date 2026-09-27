import { describe, expect, it } from 'vitest';
import { FINDING_SNIPPET_MAX_LENGTH, FindingModel } from '../finding.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const minimalFinding = () => ({
  repository: oid(),
  fingerprint: 'semgrep:sqli:src/db/users.ts:42',
  firstSeenScan: oid(),
  lastSeenScan: oid(),
  source: 'semgrep',
  ruleId: 'javascript.lang.security.audit.sqli',
  category: 'security',
  severity: 'high',
  title: 'SQL injection via string concatenation',
});

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

describe('Finding model', () => {
  it('accepts a minimal finding and applies defaults', () => {
    const finding = new FindingModel(minimalFinding());

    expect(invalidPaths(finding)).toEqual([]);
    expect(finding.status).toBe('open');
    expect(finding.confidence).toBe(1);
    expect(finding.timesDetected).toBe(1);
    expect(finding.fingerprintVersion).toBe(1);
    expect(finding.firstDetectedAt).toBeInstanceOf(Date);
    expect(finding.lastDetectedAt).toBeInstanceOf(Date);
    expect(finding.aiAnalysis?.status).toBe('not_requested');
    expect(finding.remediation?.steps).toEqual([]);
    expect(finding.aiAnalysis?.provider).toBeUndefined();
  });

  it('requires repository, fingerprint, scans, source, ruleId, category, severity and title', () => {
    expect(invalidPaths(new FindingModel({}))).toEqual([
      'category',
      'fingerprint',
      'firstSeenScan',
      'lastSeenScan',
      'repository',
      'ruleId',
      'severity',
      'source',
      'title',
    ]);
  });

  describe('classification', () => {
    it('rejects an unknown scanner, category, severity or status', () => {
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), source: 'nmap' }))).toContain(
        'source',
      );
      expect(
        invalidPaths(new FindingModel({ ...minimalFinding(), category: 'vibes' })),
      ).toContain('category');
      expect(
        invalidPaths(new FindingModel({ ...minimalFinding(), severity: 'catastrophic' })),
      ).toContain('severity');
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), status: 'triage' }))).toContain(
        'status',
      );
    });

    it('bounds confidence to 0..1', () => {
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), confidence: 1.5 }))).toContain(
        'confidence',
      );
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), confidence: 0.4 }))).toEqual([]);
    });

    it('validates the CWE identifier', () => {
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), cwe: 'CWE-79' }))).toEqual([]);
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), cwe: '79' }))).toContain('cwe');
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), cwe: 'CWE-abc' }))).toContain(
        'cwe',
      );
    });

    it('accepts dependency context', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        source: 'dependency',
        category: 'dependency',
        dependency: {
          packageName: 'lodash',
          installedVersion: '4.17.20',
          fixedVersion: '4.17.21',
          ecosystem: 'npm',
          vulnerabilityIds: ['CVE-2021-23337'],
          cvssScore: 7.2,
        },
      });

      expect(invalidPaths(finding)).toEqual([]);
      expect(finding.dependency?.ecosystem).toBe('npm');
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), dependency: { cvssScore: 11 } }))).toContain(
        'dependency.cvssScore',
      );
    });
  });

  describe('location', () => {
    it('requires a file path when a location is given', () => {
      const finding = new FindingModel({ ...minimalFinding(), location: { startLine: 10 } });

      expect(invalidPaths(finding)).toContain('location.filePath');
    });

    it('rejects a backwards line range', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        location: { filePath: 'src/a.ts', startLine: 20, endLine: 10 },
      });

      expect(invalidPaths(finding)).toContain('location.endLine');
    });

    it('caps the stored snippet length', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        location: { filePath: 'src/a.ts', snippet: 'x'.repeat(FINDING_SNIPPET_MAX_LENGTH + 1) },
      });

      expect(invalidPaths(finding)).toContain('location.snippet');
    });

    it('stores a clean snippet verbatim and unmarked', () => {
      const snippet = 'const users = await db.query(sql, [id]);';
      const finding = new FindingModel({
        ...minimalFinding(),
        location: { filePath: 'src/db/users.ts', startLine: 42, snippet },
      });

      expect(invalidPaths(finding)).toEqual([]);
      expect(finding.location?.snippet).toBe(snippet);
      expect(finding.location?.snippetRedacted).toBe(false);
    });

    it('redacts a credential that a scanner pasted into the snippet', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        location: {
          filePath: 'src/config.ts',
          startLine: 3,
          snippet: `const awsKey = "${AWS_KEY}";`,
        },
      });

      expect(invalidPaths(finding)).toEqual([]);
      expect(finding.location?.snippet).not.toContain(AWS_KEY);
      expect(finding.location?.snippet).toContain('[REDACTED]');
      expect(finding.location?.snippetRedacted).toBe(true);
    });
  });

  describe('detection lifetime', () => {
    it('rejects a lastDetectedAt that precedes firstDetectedAt', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        firstDetectedAt: new Date('2026-02-01T00:00:00.000Z'),
        lastDetectedAt: new Date('2026-01-01T00:00:00.000Z'),
      });

      expect(invalidPaths(finding)).toContain('lastDetectedAt');
    });

    it('accepts the same finding observed by several scans over time', () => {
      const finding = new FindingModel({
        ...minimalFinding(),
        firstDetectedAt: new Date('2026-01-01T00:00:00.000Z'),
        lastDetectedAt: new Date('2026-03-01T00:00:00.000Z'),
        timesDetected: 7,
      });

      expect(invalidPaths(finding)).toEqual([]);
      expect(finding.timesDetected).toBe(7);
    });
  });

  describe('triage', () => {
    it('requires resolvedAt for every closed status', () => {
      expect(invalidPaths(new FindingModel({ ...minimalFinding(), status: 'fixed' }))).toContain(
        'resolvedAt',
      );

      const resolved = new FindingModel({
        ...minimalFinding(),
        status: 'risk_accepted',
        resolvedAt: new Date('2026-01-05T00:00:00.000Z'),
        statusNote: 'Compensating control in the WAF',
      });

      expect(invalidPaths(resolved)).toEqual([]);
    });

    it('keeps a finding open while it is still present', () => {
      const finding = new FindingModel({ ...minimalFinding(), status: 'open' });

      expect(invalidPaths(finding)).toEqual([]);
      expect(finding.resolvedAt).toBeUndefined();
    });
  });

  it('carries scanner and AI provenance without raw output', () => {
    const finding = new FindingModel({
      ...minimalFinding(),
      scannerMetadata: {
        engine: 'semgrep',
        toolVersion: '1.90.0',
        ruleSet: 'p/security-audit',
        rawSeverity: 'ERROR',
        properties: { owasp: 'A03:2021' },
      },
      aiAnalysis: {
        status: 'completed',
        provider: 'openai',
        model: 'gpt-4o',
        exploitability: 'high',
        reachability: 'reachable',
        falsePositiveLikelihood: 0.1,
        confidence: 0.87,
      },
    });

    expect(invalidPaths(finding)).toEqual([]);
    expect(finding.scannerMetadata?.toolVersion).toBe('1.90.0');
    expect(finding.aiAnalysis?.falsePositiveLikelihood).toBe(0.1);
    // There is deliberately no field for a raw scanner dump.
    expect(Object.keys(FindingModel.schema.paths).some((path) => /raw(Dump|Output)/.test(path))).toBe(
      false,
    );
  });

  it('declares the dedupe key that makes a finding durable', () => {
    const index = indexNamed(FindingModel, 'uniq_repository_fingerprint');

    expect(index?.key).toBe('repository:1,fingerprint:1');
    expect(index?.options.unique).toBe(true);
  });

  it('indexes the list, per-scan and file views', () => {
    expect(indexNamed(FindingModel, 'repository_status_severity')?.key).toBe(
      'repository:1,status:1,severity:1,lastDetectedAt:-1',
    );
    expect(indexNamed(FindingModel, 'last_seen_scan')?.key).toBe('lastSeenScan:1');
    expect(indexNamed(FindingModel, 'repository_file_status')?.key).toBe(
      'repository:1,location.filePath:1,status:1',
    );
  });

  it('serialises with a string id and no internal fields', () => {
    const json = new FindingModel(minimalFinding()).toJSON() as Record<string, unknown>;

    expect(typeof json.id).toBe('string');
    expect(json).not.toHaveProperty('_id');
    expect(json).not.toHaveProperty('__v');
  });
});
