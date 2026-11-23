/** What writing `after` over a file that held `before` (`undefined` when absent) does to it. */
export type FileAction = "create" | "unchanged" | "update";

export function fileAction(before: string | undefined, after: string): FileAction {
  if (before === undefined) {
    return "create";
  }
  return before === after ? "unchanged" : "update";
}
