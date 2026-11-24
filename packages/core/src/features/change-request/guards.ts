/**
 * Guards on who may ask for a change request and which option fields they may set. They live apart
 * from the change-request flow so every surface can apply them before any git work starts.
 */

/**
 * Change requests commit and push, so they must never run for dry-run/preview/plan flows.
 * Enforced here (not only in the CLI) so SDK, MCP and HTTP callers get the same guarantee.
 */
export function assertChangeRequestAllowed(options: {
  dryRun?: boolean;
  preview?: boolean;
  changeRequest?: { enabled?: boolean };
}): void {
  if (options.changeRequest?.enabled && (options.dryRun || options.preview)) {
    throw new Error(
      "changeRequest cannot be combined with dryRun/preview (or planRemediation): change requests commit and push.",
    );
  }
}

/**
 * Remove option fields that redirect credentials or API traffic. These are host configuration,
 * never something an untrusted MCP/HTTP caller may set. Walks nested objects (e.g. portfolio targets).
 */
export function stripUntrustedChangeRequestFields<T>(value: T): T;
export function stripUntrustedChangeRequestFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => stripUntrustedChangeRequestFields(entry));
  }
  if (typeof value !== "object" || value === null) return value;
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (key === "changeRequest" && typeof entry === "object" && entry !== null) {
      out[key] = withoutHostRedirects(entry);
    } else {
      out[key] = stripUntrustedChangeRequestFields(entry);
    }
  }
  return out;
}

function withoutHostRedirects(changeRequest: object): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(changeRequest).filter(
      ([key]) => key !== "tokenEnvVar" && key !== "githubApiUrl",
    ),
  );
}
