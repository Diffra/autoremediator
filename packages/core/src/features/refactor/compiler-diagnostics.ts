/**
 * Parses compiler/typecheck output into structured diagnostics the codemods can act on.
 */

export interface ParsedTsDiagnostic {
  filePath?: string;
  line?: number;
  column?: number;
  code?: string;
  message: string;
  suggestedSymbol?: string;
  missingMember?: string;
}

/**
 * Parses compiler/typecheck diagnostic output into structured errors.
 */
export function parseCompilerDiagnostics(diagnosticError: string): ParsedTsDiagnostic[] {
  const diagnostics: ParsedTsDiagnostic[] = [];
  const lines = diagnosticError.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    // Pattern 1: path/to/file.ts(line,col): error TSxxxx: message
    // Pattern 2: path/to/file.ts:line:col - error TSxxxx: message
    const match =
      /(?:([^\s:(]+)[:(](\d+)[:,](\d+)\)?:?\s*(?:-\s*)?(?:error\s+)?(TS\d+)?:?\s*(.*))/i.exec(
        trimmed,
      );

    if (match) {
      const [, filePath, lineStr, colStr, code, message] = match;
      const diag: ParsedTsDiagnostic = {
        filePath,
        line: lineStr ? Number.parseInt(lineStr, 10) : undefined,
        column: colStr ? Number.parseInt(colStr, 10) : undefined,
        code,
        message: message || trimmed,
      };

      // Extract "Did you mean 'xyz'?"
      const suggestionMatch = /Did you mean ['"]([a-zA-Z0-9_$]+)['"]\?/i.exec(diag.message);
      if (suggestionMatch) {
        diag.suggestedSymbol = suggestionMatch[1];
      }

      // Extract missing exported member or property
      const missingMatch =
        /has no exported member ['"]([a-zA-Z0-9_$]+)['"]/i.exec(diag.message) ??
        /Property ['"]([a-zA-Z0-9_$]+)['"] does not exist/i.exec(diag.message);
      if (missingMatch) {
        diag.missingMember = missingMatch[1];
      }

      diagnostics.push(diag);
    }
  }

  return diagnostics;
}
