export interface DiffHunkRange {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
}

export interface FileDiffInfo {
  filePath: string;
  oldPath?: string;
  isNew: boolean;
  isDeleted: boolean;
  addedLines: Set<number>;
  deletedLines: Set<number>;
  hunks: DiffHunkRange[];
}

export interface ParsedGitDiff {
  files: Map<string, FileDiffInfo>;
  changedFiles: string[];
}

/**
 * Normalizes a file path for cross-platform comparison.
 */
function cleanPath(raw: string): string {
  return raw
    .replace(/\\/g, '/')
    .replace(/^a\//, '')
    .replace(/^b\//, '')
    .replace(/^\.\//, '')
    .replace(/^\//, '')
    .trim();
}

/**
 * Parses unified git diff content into structured line maps and hunk ranges.
 */
export function parseGitDiff(diffContent?: string): ParsedGitDiff {
  const files = new Map<string, FileDiffInfo>();
  if (!diffContent || !diffContent.trim()) {
    return { files, changedFiles: [] };
  }

  const lines = diffContent.split(/\r?\n/);
  let currentFile: FileDiffInfo | null = null;
  let currentNewLineNum = 0;
  let currentOldLineNum = 0;

  for (const line of lines) {
    // 1. Detect file header: diff --git a/file b/file
    if (line.startsWith('diff --git ')) {
      const match = line.match(/^diff --git a\/(.+?) b\/(.+?)$/);
      if (match) {
        const filePath = cleanPath(match[2] || match[1] || '');
        currentFile = {
          filePath,
          oldPath: cleanPath(match[1] || ''),
          isNew: false,
          isDeleted: false,
          addedLines: new Set<number>(),
          deletedLines: new Set<number>(),
          hunks: [],
        };
        files.set(filePath.toLowerCase(), currentFile);
      }
      continue;
    }

    if (!currentFile) continue;

    // Detect new file / deleted file modes
    if (line.startsWith('new file mode ')) {
      currentFile.isNew = true;
      continue;
    }
    if (line.startsWith('deleted file mode ')) {
      currentFile.isDeleted = true;
      continue;
    }

    // 2. Detect hunk header: @@ -oldStart,oldLines +newStart,newLines @@
    if (line.startsWith('@@ ')) {
      const match = line.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
      if (match) {
        const oldStart = parseInt(match[1] || '1', 10);
        const oldLines = match[2] ? parseInt(match[2], 10) : 1;
        const newStart = parseInt(match[3] || '1', 10);
        const newLines = match[4] ? parseInt(match[4], 10) : 1;

        currentOldLineNum = oldStart;
        currentNewLineNum = newStart;

        currentFile.hunks.push({
          oldStart,
          oldLines,
          newStart,
          newLines,
        });
      }
      continue;
    }

    // 3. Process diff lines within a hunk
    if (line.startsWith('+') && !line.startsWith('+++ ')) {
      currentFile.addedLines.add(currentNewLineNum);
      currentNewLineNum++;
    } else if (line.startsWith('-') && !line.startsWith('--- ')) {
      currentFile.deletedLines.add(currentOldLineNum);
      currentOldLineNum++;
    } else if (line.startsWith(' ')) {
      // Unchanged context line
      currentNewLineNum++;
      currentOldLineNum++;
    }
  }

  const changedFiles = Array.from(files.values()).map((f) => f.filePath);
  return { files, changedFiles };
}

/**
 * Checks whether a given finding line falls within or directly adjacent to added/modified lines in a file.
 */
export function isLineInDiffHunk(
  filePath: string,
  targetLine: number,
  parsedDiff: ParsedGitDiff,
  tolerance = 2,
): { isChanged: boolean; reason: string } {
  const norm = cleanPath(filePath).toLowerCase();
  const fileDiff = parsedDiff.files.get(norm);

  if (!fileDiff) {
    return {
      isChanged: false,
      reason: `File "${filePath}" is not in the PR git diff`,
    };
  }

  if (fileDiff.isNew) {
    return {
      isChanged: true,
      reason: `File "${filePath}" is newly added in this PR`,
    };
  }

  // Exact line added in this PR
  if (fileDiff.addedLines.has(targetLine)) {
    return {
      isChanged: true,
      reason: `Line ${targetLine} was added/modified directly in this PR`,
    };
  }

  // Check tolerance window around added lines (for multi-line statements or expression anchors)
  for (let offset = 1; offset <= tolerance; offset++) {
    if (fileDiff.addedLines.has(targetLine - offset) || fileDiff.addedLines.has(targetLine + offset)) {
      return {
        isChanged: true,
        reason: `Line ${targetLine} is directly within modified expression context (adjacent to added lines)`,
      };
    }
  }

  // Check if line falls within any hunk's modified range
  for (const hunk of fileDiff.hunks) {
    if (targetLine >= hunk.newStart && targetLine <= hunk.newStart + hunk.newLines) {
      return {
        isChanged: true,
        reason: `Line ${targetLine} is within modified hunk [${hunk.newStart}, ${hunk.newStart + hunk.newLines}]`,
      };
    }
  }

  return {
    isChanged: false,
    reason: `File was modified, but line ${targetLine} is outside of the PR diff hunks`,
  };
}
