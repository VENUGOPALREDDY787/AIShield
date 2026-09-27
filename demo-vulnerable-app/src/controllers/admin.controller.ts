import { Request, Response } from 'express';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

// Valid host pattern: strict IPv4 or standard hostname
const HOSTNAME_REGEX = /^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))*$/;

/**
 * System diagnostic network ping utility.
 * ✅ REMEDIATED: Command injection eliminated via strict validation + execFile (no shell interpolation).
 */
export function pingHost(req: Request, res: Response) {
  const host = req.query.host as string;

  if (!host || typeof host !== 'string' || !HOSTNAME_REGEX.test(host.trim())) {
    return res.status(400).json({ error: 'Valid hostname or IP required' });
  }

  // Safe: execFile passes arguments as an array without invoking a shell interpreter
  execFile('ping', ['-c', '3', host.trim()], (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: 'Ping diagnostics execution failed' });
    }
    res.json({ output: stdout });
  });
}

const ALLOWED_LOG_DIR = path.resolve('/var/log/app');
const ALLOWED_LOG_FILES = new Set(['app.log', 'access.log', 'error.log', 'audit.log']);

/**
 * Admin log viewer.
 * ✅ REMEDIATED: Path traversal eliminated via strict basename whitelist & directory containment validation.
 */
export function viewLogFile(req: Request, res: Response) {
  const filename = req.query.file as string;

  if (!filename || typeof filename !== 'string') {
    return res.status(400).json({ error: 'file parameter is required' });
  }

  const baseName = path.basename(filename);
  if (!ALLOWED_LOG_FILES.has(baseName)) {
    return res.status(403).json({ error: 'Access to requested log file is forbidden' });
  }

  const targetPath = path.join(ALLOWED_LOG_DIR, baseName);
  const relative = path.relative(ALLOWED_LOG_DIR, targetPath);

  // Ensure resolved path is strictly within the allowed directory
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    return res.status(403).json({ error: 'Directory traversal detected' });
  }

  try {
    const content = fs.readFileSync(targetPath, 'utf-8');
    res.type('text/plain').send(content);
  } catch (err: any) {
    res.status(404).json({ error: 'Log file not found' });
  }
}
