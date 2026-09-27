import { describe, it, expect } from 'vitest';
import {
  isValidGitSha,
  isValidGitRef,
  validateRepositoryUrl,
  sanitizeRelativePath,
} from '@aishield/shared';

describe('Security Validation & SSRF Guard', () => {
  describe('isValidGitSha', () => {
    it('accepts valid 40-character hex SHAs', () => {
      expect(isValidGitSha('4b825dc642cb6eb9a060e54bf8d69288fbee4904')).toBe(true);
      expect(isValidGitSha('A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2')).toBe(true);
    });

    it('accepts valid 7-character short SHAs', () => {
      expect(isValidGitSha('4b825dc')).toBe(true);
    });

    it('rejects SHAs containing command injection or shell metacharacters', () => {
      expect(isValidGitSha('4b825dc; rm -rf /')).toBe(false);
      expect(isValidGitSha('$(whoami)')).toBe(false);
      expect(isValidGitSha('`id`')).toBe(false);
      expect(isValidGitSha('--output=/tmp/evil')).toBe(false);
      expect(isValidGitSha('../../../etc/passwd')).toBe(false);
    });
  });

  describe('isValidGitRef', () => {
    it('accepts valid branch names', () => {
      expect(isValidGitRef('main')).toBe(true);
      expect(isValidGitRef('feature/add-oauth')).toBe(true);
      expect(isValidGitRef('release-v1.2.0')).toBe(true);
    });

    it('rejects dangerous branch names with flag injection or shell tricks', () => {
      expect(isValidGitRef('-flag')).toBe(false);
      expect(isValidGitRef('--upload-pack=evil')).toBe(false);
      expect(isValidGitRef('main; rm -rf /')).toBe(false);
      expect(isValidGitRef('refs/heads/../evil')).toBe(false);
      expect(isValidGitRef('.hidden')).toBe(false);
      expect(isValidGitRef('branch with spaces')).toBe(false);
    });
  });

  describe('validateRepositoryUrl (SSRF Guard)', () => {
    it('allows safe HTTPS git repositories', () => {
      expect(validateRepositoryUrl('https://github.com/aishield/core.git').valid).toBe(true);
      expect(validateRepositoryUrl('https://gitlab.com/group/repo').valid).toBe(true);
      expect(validateRepositoryUrl('git@github.com:org/repo.git').valid).toBe(true);
    });

    it('blocks AWS/GCP/Azure cloud metadata endpoints', () => {
      const res = validateRepositoryUrl('http://169.254.169.254/latest/meta-data/');
      expect(res.valid).toBe(false);
    });

    it('blocks localhost and loopback IPv4/IPv6', () => {
      expect(validateRepositoryUrl('https://localhost:8080/repo.git').valid).toBe(false);
      expect(validateRepositoryUrl('https://127.0.0.1:3000/repo.git').valid).toBe(false);
      expect(validateRepositoryUrl('https://[::1]/repo.git').valid).toBe(false);
    });

    it('blocks RFC1918 private subnets', () => {
      expect(validateRepositoryUrl('https://10.0.0.5/repo.git').valid).toBe(false);
      expect(validateRepositoryUrl('https://172.16.0.1/repo.git').valid).toBe(false);
      expect(validateRepositoryUrl('https://192.168.1.100/repo.git').valid).toBe(false);
    });

    it('blocks dangerous URL schemes (file, gopher, ftp)', () => {
      expect(validateRepositoryUrl('file:///etc/passwd').valid).toBe(false);
      expect(validateRepositoryUrl('gopher://internal.lan/').valid).toBe(false);
      expect(validateRepositoryUrl('ftp://ftp.example.com/repo').valid).toBe(false);
    });
  });

  describe('sanitizeRelativePath (Path Traversal Guard)', () => {
    it('normalizes valid relative paths', () => {
      expect(sanitizeRelativePath('src/index.ts')).toBe('src/index.ts');
      expect(sanitizeRelativePath('./app/worker.ts')).toBe('app/worker.ts');
      expect(sanitizeRelativePath('nested\\file.js')).toBe('nested/file.js');
    });

    it('rejects directory traversal attempts', () => {
      expect(sanitizeRelativePath('../../../etc/passwd')).toBe(null);
      expect(sanitizeRelativePath('src/../../secrets.env')).toBe(null);
      expect(sanitizeRelativePath('/etc/shadow')).toBe(null);
      expect(sanitizeRelativePath('-flag/test.txt')).toBe(null);
    });
  });
});
