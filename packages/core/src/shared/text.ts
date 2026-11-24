/** `1 file`, `2 files`. Pass `plural` when adding "s" is not enough (`1 entry`, `2 entries`). */
export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Orders strings by UTF-16 code unit, the same order as the default `Array#sort`. */
export function compareStrings(a: string, b: string): number {
  if (a < b) {
    return -1;
  }
  return a > b ? 1 : 0;
}
