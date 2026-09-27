/**
 * AIShield Live Directory Scanner CLI
 * 
 * Usage:
 *   npx tsx scripts/scan.ts [target-directory]
 * 
 * Example:
 *   npx tsx scripts/scan.ts demo-vulnerable-app
 *   npx tsx scripts/scan.ts ./apps/api
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { calculateSecurityDebtScore } from '../apps/worker/src/engine/debt-scoring-engine.js';
import type { NormalizedFinding, Severity, FindingCategory } from '@aishield/shared';

interface ScanRule {
  id: string;
  category: FindingCategory;
  severity: Severity;
  cwe: string;
  title: string;
  description: string;
  pattern: RegExp;
  remediation: string;
}

const STATIC_RULES: ScanRule[] = [
  {
    id: 'aishield-sqli',
    category: 'sast',
    severity: 'critical',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    title: 'SQL Injection via String Concatenation / Template Literal',
    description: 'User input is concatenated directly into an SQL statement without parameterization.',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+.*(?:\+\s*[\w\.]+|\$\{[^\}]+\})/i,
    remediation: 'Use parameterized queries or prepared statements ($1, ? placeholders) instead of string concatenation.',
  },
  {
    id: 'aishield-command-injection',
    category: 'sast',
    severity: 'critical',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    title: 'OS Command Injection',
    description: 'Dynamic input is passed directly to exec() / spawn() without sanitization.',
    pattern: /exec\s*\(\s*['"`].*(?:\+|`|\$\{)/,
    remediation: 'Use execFile() with discrete arguments array or strictly sanitize/whitelist input before passing to shell.',
  },
  {
    id: 'aishield-hardcoded-secret',
    category: 'secret',
    severity: 'critical',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    title: 'Hardcoded Secret / Token Detected',
    description: 'A static API token or credential was discovered in source code.',
    pattern: /(?:JWT_SECRET|API_KEY|SECRET_KEY|token|password)\s*=\s*['"][a-zA-Z0-9_\-\.]{16,}['"]/i,
    remediation: 'Remove hardcoded credentials and read them dynamically from environment variables (process.env).',
  },
  {
    id: 'aishield-weak-crypto',
    category: 'sast',
    severity: 'medium',
    cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    title: 'Weak Cryptographic Algorithm (MD5/SHA1/DES)',
    description: 'A broken or collision-prone hashing or encryption algorithm was detected.',
    pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|createCipheriv\s*\(\s*['"]des/i,
    remediation: 'Upgrade to collision-resistant algorithms such as SHA-256 / SHA-3 or AES-256-GCM for encryption.',
  },
  {
    id: 'aishield-eval-injection',
    category: 'sast',
    severity: 'critical',
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    title: 'Dangerous eval() Execution',
    description: 'eval() dynamically evaluates untrusted code and can lead to Remote Code Execution.',
    pattern: /\beval\s*\(/,
    remediation: 'Avoid eval() entirely. Use JSON.parse() or dedicated domain-specific parsers.',
  },
  {
    id: 'aishield-reflected-xss',
    category: 'sast',
    severity: 'high',
    cwe: 'CWE-79: Cross-site Scripting (XSS)',
    title: 'Reflected Cross-Site Scripting (XSS)',
    description: 'Unescaped user input is rendered directly into HTML responses.',
    pattern: /res\.(?:send|write)\s*\(\s*['"`]<.*(?:\+|`|\$\{)/i,
    remediation: 'Encode and sanitize all dynamic content before embedding it into HTML output, or use a templating engine with auto-escaping.',
  },
  {
    id: 'aishield-missing-idor-auth',
    category: 'ai_contextual',
    severity: 'high',
    cwe: 'CWE-285: Improper Authorization (IDOR)',
    title: 'Potential Insecure Direct Object Reference (IDOR)',
    description: 'Resource is fetched by user-supplied ID without verifying ownership or tenant isolation.',
    pattern: /req\.params\.(?:userId|accountId|id)(?![\s\S]{0,120}(?:currentUser|req\.user|permission|role|=== targetUserId))/,
    remediation: 'Enforce authorization checks validating that the authenticated session owner matches the requested resource ID.',
  },
];

function getFilesRecursively(dir: string, fileList: string[] = []): string[] {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!['node_modules', '.git', 'dist', 'coverage', '.system_generated'].includes(entry.name)) {
        getFilesRecursively(fullPath, fileList);
      }
    } else if (/\.(ts|js|jsx|tsx|json|py|java|go|env)$/i.test(entry.name)) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

function scanFile(filePath: string, targetBaseDir: string): NormalizedFinding[] {
  const findings: NormalizedFinding[] = [];
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const relativePath = path.relative(targetBaseDir, filePath).replace(/\\/g, '/');

  // Check package.json for vulnerable dependencies
  if (path.basename(filePath) === 'package.json') {
    try {
      const pkg = JSON.parse(content);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (allDeps['lodash'] && (allDeps['lodash'].includes('4.17.15') || allDeps['lodash'].includes('4.17.11'))) {
        const fp = createHash('sha256').update(`${relativePath}:pkg:lodash:cve`).digest('hex').slice(0, 16);
        findings.push({
          id: `dep-${fp}`,
          fingerprint: fp,
          title: 'Vulnerable Dependency: lodash (Prototype Pollution)',
          description: 'lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution (CVE-2019-10744, CVE-2020-8203).',
          category: 'dependency',
          severity: 'high',
          status: 'open',
          source: 'dependency',
          scannerId: 'dependency',
          cweIds: ['CWE-1321'],
          location: {
            filePath: relativePath,
            startLine: 1,
            endLine: 1,
            snippet: `"lodash": "${allDeps['lodash']}"`,
          },
          suggestedFix: {
            description: 'Upgrade lodash to version 4.17.21 or higher.',
            replacement: '"lodash": "^4.17.21"',
          },
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString(),
          timesDetected: 1,
        });
      }
    } catch {
      // ignore json parse errors
    }
  }

  // Scan lines with static rules
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const lineNum = i + 1;

    for (const rule of STATIC_RULES) {
      if (rule.pattern.test(line)) {
        const fp = createHash('sha256').update(`${relativePath}:${rule.id}:${lineNum}`).digest('hex').slice(0, 16);
        findings.push({
          id: `finding-${fp}`,
          fingerprint: fp,
          title: rule.title,
          description: rule.description,
          category: rule.category,
          severity: rule.severity,
          status: 'open',
          source: rule.category === 'ai_contextual' ? 'ai_analyzer' : 'semgrep',
          scannerId: rule.category === 'secret' ? 'gitleaks' : 'semgrep',
          cweIds: [rule.cwe.split(':')[0]!],
          location: {
            filePath: relativePath,
            startLine: lineNum,
            endLine: lineNum,
            snippet: line.trim(),
          },
          suggestedFix: {
            description: rule.remediation,
          },
          firstDetectedAt: new Date().toISOString(),
          lastDetectedAt: new Date().toISOString(),
          timesDetected: 1,
        });
      }
    }
  }

  return findings;
}

async function runLiveScan() {
  const targetDirInput = process.argv[2] || 'demo-vulnerable-app';
  const targetDir = path.resolve(process.cwd(), targetDirInput);

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🛡️  AIShield Live Codebase Scanner');
  console.log(`📁 Scanning Target: ${targetDir}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  if (!fs.existsSync(targetDir)) {
    console.error(`❌ Error: Directory "${targetDir}" does not exist.`);
    process.exit(1);
  }

  const files = getFilesRecursively(targetDir);
  console.log(`🔍 Found ${files.length} source file(s) to inspect.\n`);

  let allFindings: NormalizedFinding[] = [];
  for (const file of files) {
    const fileFindings = scanFile(file, targetDir);
    allFindings.push(...fileFindings);
  }

  // Calculate Security Debt
  const debtScore = calculateSecurityDebtScore({ findings: allFindings });

  // Print Findings
  if (allFindings.length === 0) {
    console.log('✅ No security vulnerabilities detected! Repository is clean.\n');
  } else {
    console.log(`🚨 Detected ${allFindings.length} Security Issue(s):\n`);
    allFindings.forEach((f, idx) => {
      const sevColor = f.severity === 'critical' ? '🔴 CRITICAL' : f.severity === 'high' ? '🟠 HIGH' : '🟡 MEDIUM';
      console.log(` [${idx + 1}] ${sevColor}: ${f.title}`);
      console.log(`     📍 File: ${f.location.filePath}:${f.location.startLine}`);
      console.log(`     🏷️  CWE: ${f.cweIds?.join(', ') || 'N/A'}`);
      console.log(`     🔍 Code: "${f.location.snippet}"`);
      if (f.suggestedFix?.description) {
        console.log(`     💡 Fix: ${f.suggestedFix.description}`);
      }
      console.log('');
    });
  }

  // Compute Letter Grade from Debt Score
  let grade = 'A';
  if (debtScore.score > 85) grade = 'F';
  else if (debtScore.score > 60) grade = 'D';
  else if (debtScore.score > 30) grade = 'C';
  else if (debtScore.score > 10) grade = 'B';

  // Print Security Debt Score
  console.log('──────────────────────────────────────────────────────────────────────────');
  console.log(`📊 SECURITY DEBT SUMMARY`);
  console.log(`   ➜ Score:       ${debtScore.score} / 100`);
  console.log(`   ➜ Grade:       ${grade} (${debtScore.riskLevel})`);
  console.log(`   ➜ Findings:    ${allFindings.length} (${debtScore.severityBreakdown.CRITICAL} Critical, ${debtScore.severityBreakdown.HIGH} High, ${debtScore.severityBreakdown.MEDIUM} Medium, ${debtScore.severityBreakdown.LOW} Low)`);
  console.log(`   ➜ Raw Points:  ${debtScore.totalDebtPoints.toFixed(1)} pts`);

  const passed = debtScore.score < 25 && debtScore.severityBreakdown.CRITICAL === 0;
  console.log(`\n🚦 POLICY GATE VERDICT: ${passed ? '🟢 PASS (Safe to merge)' : '🔴 FAIL (Blocked - High Security Debt)'}`);
  console.log('──────────────────────────────────────────────────────────────────────────\n');
}

runLiveScan().catch((err) => {
  console.error('Fatal scanner error:', err);
  process.exit(1);
});
