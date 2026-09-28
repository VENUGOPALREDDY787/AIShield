/**
 * AIShield GitHub Action Runner (Self-Contained)
 * Executes static security scanning, calculates Security Debt, and posts GitHub PR comments & checks.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// 1. Resolve inputs and environment
const token = process.env.INPUT_GITHUB_TOKEN || process.env.GITHUB_TOKEN || '';
const eventPath = process.env.GITHUB_EVENT_PATH || '';
const repoFullName = process.env.GITHUB_REPOSITORY || '';
const failOnCritical = (process.env.INPUT_FAIL_ON_CRITICAL || process.env.FAIL_ON_CRITICAL || 'false') === 'true';
const failOnHigh = (process.env.INPUT_FAIL_ON_HIGH || process.env.FAIL_ON_HIGH || 'false') === 'true';
const failOnDebtIncrease = (process.env.INPUT_FAIL_ON_DEBT_INCREASE || process.env.FAIL_ON_DEBT_INCREASE || 'false') === 'true';
const dryRun = (process.env.INPUT_DRY_RUN || process.env.DRY_RUN || 'false') === 'true';

let prNumber = null;
let headSha = process.env.GITHUB_SHA || '';

if (eventPath && fs.existsSync(eventPath)) {
  try {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf-8'));
    if (eventData.pull_request) {
      prNumber = eventData.pull_request.number;
      headSha = eventData.pull_request.head?.sha || headSha;
    }
  } catch (err) {
    console.warn('⚠️ Could not parse GITHUB_EVENT_PATH:', err.message);
  }
}

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('🛡️  AIShield Security Debt & PR Gate');
console.log(`📁 Repository: ${repoFullName || 'Local'}`);
console.log(`🌿 PR Number:  ${prNumber ? `#${prNumber}` : 'N/A (Push event)'}`);
console.log(`📌 Commit SHA: ${headSha.slice(0, 7)}`);
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

// 2. Scan Rules
const STATIC_RULES = [
  {
    id: 'aishield-sqli',
    category: 'sast',
    severity: 'critical',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    title: 'SQL Injection via String Concatenation',
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
];

function getFilesRecursively(dir, fileList = []) {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!['node_modules', '.git', 'dist', 'coverage', '.system_generated'].includes(entry.name)) {
        getFilesRecursively(fullPath, fileList);
      }
    } else if (/\.(ts|js|jsx|tsx|json|py|java|go|env|ejs)$/i.test(entry.name)) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

const workspaceRoot = process.cwd();
const files = getFilesRecursively(workspaceRoot);
console.log(`🔍 Inspecting ${files.length} source file(s) in workspace...\n`);

const findings = [];
for (const file of files) {
  const relativePath = path.relative(workspaceRoot, file).replace(/\\/g, '/');
  const content = fs.readFileSync(file, 'utf-8');
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    for (const rule of STATIC_RULES) {
      if (rule.pattern.test(line)) {
        const fp = crypto.createHash('sha256').update(`${relativePath}:${rule.id}:${lineNum}`).digest('hex').slice(0, 16);
        findings.push({
          id: `finding-${fp}`,
          fingerprint: fp,
          title: rule.title,
          description: rule.description,
          category: rule.category,
          severity: rule.severity,
          cwe: rule.cwe,
          filePath: relativePath,
          line: lineNum,
          snippet: line.trim(),
          remediation: rule.remediation,
        });
      }
    }
  }
}

// 3. Debt Calculation
const SEVERITY_POINTS = { critical: 25.0, high: 12.0, medium: 5.0, low: 1.5 };
let rawPoints = 0;
const counts = { critical: 0, high: 0, medium: 0, low: 0 };

for (const f of findings) {
  rawPoints += SEVERITY_POINTS[f.severity] || 1.0;
  counts[f.severity] = (counts[f.severity] || 0) + 1;
}

// Exponential Saturation Curve: Score = 100 * (1 - e^(-points / 50))
const debtScore = rawPoints <= 0 ? 0 : Math.min(100, Math.round(100 * (1 - Math.exp(-rawPoints / 50.0))));

let grade = 'A';
let riskLevel = 'LOW';
if (debtScore > 85) { grade = 'F'; riskLevel = 'CRITICAL'; }
else if (debtScore > 60) { grade = 'D'; riskLevel = 'HIGH'; }
else if (debtScore > 30) { grade = 'C'; riskLevel = 'ELEVATED'; }
else if (debtScore > 10) { grade = 'B'; riskLevel = 'MEDIUM'; }

const policyFail = counts.critical > 0 || counts.high > 0 || debtScore > 25;
const policyStatus = policyFail ? 'FAIL' : 'PASS';

console.log('──────────────────────────────────────────────────────────────────────────');
console.log(`📊 SECURITY DEBT SUMMARY`);
console.log(`   ➜ Score:       ${debtScore} / 100`);
console.log(`   ➜ Grade:       ${grade} (${riskLevel})`);
console.log(`   ➜ Findings:    ${findings.length} (${counts.critical} Critical, ${counts.high} High, ${counts.medium} Medium)`);
console.log(`   ➜ Policy:      ${policyStatus === 'PASS' ? '🟢 PASS' : '🔴 FAIL'}`);
console.log('──────────────────────────────────────────────────────────────────────────\n');

// 4. GitHub API Helper
async function githubRequest(endpoint, method = 'GET', body = null) {
  if (!token || dryRun) return null;
  const res = await fetch(`https://api.github.com${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'AIShield-GitHub-Action',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    console.warn(`GitHub API Warning [${res.status}]: ${text}`);
    return null;
  }
  return res.json();
}

// 5. Build PR Comment Markdown
function buildPrComment() {
  const badgeColor = policyStatus === 'PASS' ? 'brightgreen' : 'red';
  const badgeUrl = `https://img.shields.io/badge/AIShield_Debt-${debtScore}%2F100_(${grade})-${badgeColor}`;

  let md = `## 🛡️ AIShield Security Debt Report\n\n`;
  md += `![AIShield Status](${badgeUrl})\n\n`;
  md += `| Metric | Value |\n`;
  md += `| :--- | :--- |\n`;
  md += `| **Security Debt Score** | **${debtScore} / 100** (Grade: **${grade}**) |\n`;
  md += `| **Risk Level** | **${riskLevel}** |\n`;
  md += `| **Policy Verdict** | ${policyStatus === 'PASS' ? '🟢 **APPROVED (PASS)**' : '🔴 **BLOCKED (FAIL)**'} |\n`;
  md += `| **Total Findings** | **${findings.length}** (${counts.critical} Critical, ${counts.high} High, ${counts.medium} Medium) |\n\n`;

  if (findings.length === 0) {
    md += `### ✅ Clean Code! No security vulnerabilities detected.\n`;
  } else {
    md += `### 🚨 Detected Vulnerabilities\n\n`;
    findings.forEach((f, idx) => {
      const sevIcon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : '🟡';
      md += `#### ${idx + 1}. ${sevIcon} ${f.title} (${f.severity.toUpperCase()})\n`;
      md += `- **Location:** \`${f.filePath}:${f.line}\`\n`;
      md += `- **Standard:** \`${f.cwe}\`\n`;
      md += `- **Code Snippet:**\n\`\`\`javascript\n${f.snippet}\n\`\`\`\n`;
      md += `- **💡 Suggested Remediation:** ${f.remediation}\n\n`;
    });
  }

  md += `\n---\n*Report generated automatically by [AIShield](https://github.com/VENUGOPALREDDY787/AIShield)*`;
  return md;
}

// 6. Post GitHub PR Comment & Check Run
async function reportToGitHub() {
  if (!token || dryRun) {
    console.log('ℹ️ Running in dry-run mode or no GITHUB_TOKEN provided. Skipping GitHub API posting.');
    return;
  }

  if (prNumber && repoFullName) {
    console.log(`💬 Posting AIShield report comment to PR #${prNumber}...`);
    const commentBody = buildPrComment();

    // Check for existing sticky comment to update
    const comments = await githubRequest(`/repos/${repoFullName}/issues/${prNumber}/comments`) || [];
    const existing = comments.find(c => c.body && c.body.includes('🛡️ AIShield Security Debt Report'));

    if (existing) {
      await githubRequest(`/repos/${repoFullName}/issues/comments/${existing.id}`, 'PATCH', { body: commentBody });
      console.log('✓ Sticky PR comment updated successfully.');
    } else {
      await githubRequest(`/repos/${repoFullName}/issues/${prNumber}/comments`, 'POST', { body: commentBody });
      console.log('✓ PR comment posted successfully.');
    }
  }

  // Set GitHub Check Run
  if (headSha && repoFullName) {
    console.log(`📊 Updating GitHub Check Run for commit ${headSha.slice(0, 7)}...`);
    const conclusion = policyStatus === 'PASS' ? 'success' : 'failure';
    await githubRequest(`/repos/${repoFullName}/check-runs`, 'POST', {
      name: 'AIShield Security Debt Scan',
      head_sha: headSha,
      status: 'completed',
      conclusion: conclusion,
      output: {
        title: `[${policyStatus}] Security Debt: ${debtScore}/100 (${riskLevel})`,
        summary: `AIShield completed scan with ${findings.length} finding(s). Policy Verdict: ${policyStatus}`,
        text: buildPrComment(),
      },
    });
    console.log(`✓ GitHub Check Run updated: ${conclusion.toUpperCase()}`);
  }
}

reportToGitHub()
  .then(() => {
    if (policyFail && (failOnCritical || failOnHigh || failOnDebtIncrease)) {
      console.error(`\n❌ Action failed: Security policy violation detected (Score: ${debtScore}/100, Critical: ${counts.critical}, High: ${counts.high}).`);
      process.exit(1);
    }
    console.log('\n🎉 AIShield scan completed successfully.');
  })
  .catch((err) => {
    console.error('Fatal error during action execution:', err);
    process.exit(1);
  });
