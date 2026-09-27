import { execFile } from 'node:child_process';
import type { CommandExecutionOptions, CommandExecutor, CommandResult } from './types.js';

export const defaultCommandExecutor: CommandExecutor = (
  command: string,
  args: string[],
  options: CommandExecutionOptions,
): Promise<CommandResult> => {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      {
        cwd: options.cwd,
        timeout: options.timeoutMs ?? 120_000,
        maxBuffer: 50 * 1024 * 1024, // 50MB
        signal: options.signal,
      },
      (error, stdout, stderr) => {
        if (error) {
          // If executable not found (ENOENT), reject immediately so scanner can report missing binary
          if ((error as { code?: string }).code === 'ENOENT') {
            return reject(error);
          }
          // If the child was killed via timeout or signal, or returned a non-zero exit code
          if (error.name === 'AbortError' || (error as { killed?: boolean }).killed) {
            return reject(new Error(`Command timed out or aborted: ${command}`));
          }
          // Some scanners exit with 1 or 2 when findings are detected (e.g. Semgrep, Gitleaks)
          // We return the output and let the scanner adapter determine if it is a failure or finding report
          return resolve({
            stdout: stdout ? stdout.toString() : '',
            stderr: stderr ? stderr.toString() : '',
            exitCode: error.code && typeof error.code === 'number' ? error.code : 1,
          });
        }

        resolve({
          stdout: stdout ? stdout.toString() : '',
          stderr: stderr ? stderr.toString() : '',
          exitCode: 0,
        });
      },
    );

    child.on('error', (err) => {
      reject(err);
    });
  });
};
