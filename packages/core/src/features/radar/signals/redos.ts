/**
 * Regular-expression shapes that backtrack badly. The code diff uses this to tell a fix that
 * replaces a vulnerable expression from an unrelated expression change.
 */

/**
 * Whether a regular expression has a shape known to backtrack catastrophically or quadratically:
 * a quantified group that itself contains a quantifier, two adjacent identical quantified atoms
 * (`\s*\s*`), or an unanchored `\s+$` / `\s*$`. Conservative: it names shapes, it does not prove
 * a bound.
 */
export function isRedosProne(source: string): boolean {
  if (/(\\[sdwSDW]|\.|\[[^\]]*\])[*+]\??\1[*+]/.test(source)) return true;
  if (!source.startsWith("^") && /(?:\\s|\[ \\t\]|\[\\s\])[*+]\$$/.test(source)) return true;

  const groups: Array<{ quantified: boolean }> = [];
  for (let index = 0; index < source.length; index++) {
    const char = source[index];
    if (char === "\\") {
      index++;
    } else if (char === "[") {
      // Skip a character class; `]` first is literal.
      index++;
      if (source[index] === "^") index++;
      if (source[index] === "]") index++;
      while (index < source.length && source[index] !== "]") {
        if (source[index] === "\\") index++;
        index++;
      }
    } else if (char === "(") {
      groups.push({ quantified: false });
    } else if (
      char === "+" ||
      char === "*" ||
      (char === "{" && /^\{\d+,\d*\}/.test(source.slice(index)))
    ) {
      const top = groups.at(-1);
      if (top) top.quantified = true;
    } else if (char === ")") {
      const closed = groups.pop();
      const next = source.slice(index + 1);
      if (closed?.quantified && /^(?:[+*]|\{\d+,\d*\})/.test(next)) return true;
      // The inner quantifier counts for the enclosing group too.
      const parent = groups.at(-1);
      if (closed?.quantified && parent) parent.quantified = true;
    }
  }
  return false;
}
