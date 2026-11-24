/**
 * Changelog signals for the releases between two versions: the changelog shipped in the newest
 * tarball first, then GitHub release notes for the releases it does not cover (when asked for).
 */
import semver from "semver";

import type { Run } from "./run.js";
import { changelogFlags, parseChangelog } from "./signals/changelog.js";
import { sanitizeEvidence } from "./signals/sanitize.js";
import type { RadarFlag } from "./signals/types.js";

interface Repository {
  owner: string;
  repo: string;
}

interface OwnChangelog {
  name: string;
  sections: ReturnType<typeof parseChangelog>;
  covered: Set<string>;
}

export async function releaseNotesFlags(
  run: Run,
  installed: string,
  target: string,
  range: readonly string[],
  docs: ReadonlyMap<string, string>,
  repository: Repository | undefined,
): Promise<{ flags: RadarFlag[]; found: boolean; note?: string }> {
  const best = bestChangelog(docs, installed, target);
  const flags = best
    ? changelogFlags({
        source: sanitizeEvidence(best.name, 60),
        sections: best.sections,
        from: installed,
        to: target,
      })
    : [];
  let found = (best?.covered.size ?? 0) > 0;
  let note: string | undefined;

  const missing = range.filter((version) => !best?.covered.has(version));
  if (run.options.github && repository && missing.length > 0) {
    const fetched = await run.deps.fetchGithubReleases(repository);
    if (fetched.note) note = fetched.note;
    for (const release of fetched.releases) {
      const version = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(release.tag)?.[1];
      if (!version || !missing.includes(version)) continue;
      found = true;
      flags.push(...githubReleaseFlags(repository, release, version, installed, target));
    }
  }
  return { flags, found, ...(note ? { note } : {}) };
}

/** The GitHub repository named by a package manifest, when it is one. */
export function repositoryOf(manifest: Record<string, unknown>): Repository | undefined {
  const raw = manifest["repository"];
  const url = typeof raw === "string" ? raw : (raw as { url?: unknown } | undefined)?.url;
  if (typeof url !== "string") return undefined;
  const match =
    /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$/.exec(url) ??
    /^github:([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(url) ??
    /^([A-Za-z0-9_-]+)\/([A-Za-z0-9_.-]+)$/.exec(url);
  return match?.[1] && match[2] ? { owner: match[1], repo: match[2] } : undefined;
}

/** The tarball's own changelog: the document that covers the most releases in range. */
function bestChangelog(
  docs: ReadonlyMap<string, string>,
  installed: string,
  target: string,
): OwnChangelog | undefined {
  let best: OwnChangelog | undefined;
  for (const [name, text] of docs) {
    const sections = parseChangelog(text);
    const covered = new Set(
      sections
        .filter(
          (section) => semver.gt(section.version, installed) && semver.lte(section.version, target),
        )
        .map((section) => section.version),
    );
    if (covered.size > (best?.covered.size ?? 0)) best = { name, sections, covered };
  }
  return best;
}

function githubReleaseFlags(
  repository: Repository,
  release: { tag: string; body: string },
  version: string,
  installed: string,
  target: string,
): RadarFlag[] {
  return changelogFlags({
    source: `github:${repository.owner}/${repository.repo}@${sanitizeEvidence(release.tag, 40)}`,
    sections: [
      {
        version,
        startLine: 0,
        lines: release.body
          .split(/\r?\n/)
          .slice(0, 400)
          .map((text, index) => ({ line: index + 1, text })),
      },
    ],
    from: installed,
    to: target,
  });
}
