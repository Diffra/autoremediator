import { fileAction } from "../../../shared/file-action.js";
/** Plans, applies and formats the file changes `maintain` proposes: package.json, VEX, changeset. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { PACKAGE_VERSION } from "../../../shared/version.js";
import { renderDiff } from "../../init/diff.js";
import type { FileChange } from "../../init/types.js";
import type { Manifest } from "./manifest.js";
import { changesetName, editPackageJson, renderChangeset } from "./package-files.js";
import { changesetLines, toDraft } from "./statements.js";
import type { MaintainAdvisory, MaintainResult } from "./types.js";
import { mergeVexFile, type DraftStatement } from "./vex-file.js";

export interface PlanChangesInput {
  cwd: string;
  manifest: Manifest;
  /** The version the package will release as; undefined when it could not be decided. */
  nextVersion: string | undefined;
  advisories: readonly MaintainAdvisory[];
  usesChangesets: boolean;
  now: () => Date;
  /** Receives explanations for anything left unprepared or worth checking. */
  notes: string[];
}

interface PublishContext extends PlanChangesInput {
  nextVersion: string;
  drafts: DraftStatement[];
  written: readonly MaintainAdvisory[];
}

export function planChanges(input: PlanChangesInput): FileChange[] {
  const { advisories, manifest, nextVersion, notes } = input;
  const drafts = advisories.flatMap((advisory) => {
    const draft = toDraft(advisory);
    return draft ? [draft] : [];
  });
  const written = advisories.filter((advisory) => toDraft(advisory) !== undefined);

  if (manifest.private) {
    notes.push(
      "This package is private, so it publishes nothing: no OpenVEX document or changeset was prepared.",
    );
    return [];
  }
  if (drafts.length === 0) return [];
  if (!nextVersion) {
    notes.push("No OpenVEX statements were prepared because the next version is not known.");
    return [];
  }
  return planPublishedChanges({ ...input, nextVersion, drafts, written });
}

/** Writes the create and update changes to disk; true when anything was written. */
export function applyChanges(cwd: string, changes: readonly FileChange[]): boolean {
  const pending = pendingChanges(changes);
  for (const change of pending) {
    const target = join(cwd, change.path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, change.after, "utf8");
  }
  return pending.length > 0;
}

/** The changes that would alter a file; unchanged and conflicting ones are left out. */
export function pendingChanges(changes: readonly FileChange[]): FileChange[] {
  return changes.filter((change) => change.action === "create" || change.action === "update");
}

export function formatChanges(changes: readonly FileChange[]): MaintainResult["changes"] {
  return changes.map((change) => ({
    path: change.path,
    action: change.action,
    reason: change.reason,
    diff:
      change.action === "create" || change.action === "update"
        ? renderDiff(change.path, change.before, change.after)
        : "",
  }));
}

function planPublishedChanges(context: PublishContext): FileChange[] {
  const { cwd, notes } = context;
  const changes: FileChange[] = [];
  const before = readIfExists(cwd, "package.json")!;
  const edit = editPackageJson(before);
  changes.push(
    toChange(
      "package.json",
      "declare the OpenVEX document (vex) and ship it (files)",
      before,
      edit,
    ),
  );
  if ("vexPath" in edit) {
    changes.push(planVexChange(context, edit.vexPath));
    if (existsSync(join(cwd, ".npmignore"))) {
      notes.push(`.npmignore exists: check that it does not exclude ${edit.vexPath}.`);
    }
    if (!Array.isArray((JSON.parse(before) as { files?: unknown }).files)) {
      notes.push(
        `package.json has no "files" list, so ${edit.vexPath} ships unless .npmignore or .gitignore excludes it.`,
      );
    }
  }
  if (context.usesChangesets) {
    changes.push(planChangesetChange(context));
  } else {
    notes.push(
      "This repository does not use changesets (no .changeset/config.json), so no changeset was prepared: bump the version and write release notes yourself.",
    );
  }
  return changes;
}

function planVexChange(context: PublishContext, vexPath: string): FileChange {
  const { cwd, manifest, nextVersion, written } = context;
  const existing = readIfExists(cwd, vexPath);
  const merged = mergeVexFile({
    existing,
    packageName: manifest.name,
    version: nextVersion,
    author: manifest.author,
    tooling: `autoremediator ${PACKAGE_VERSION} maintain`,
    statements: context.drafts,
    now: context.now(),
  });
  return toChange(
    vexPath,
    `OpenVEX statements for ${manifest.name}@${nextVersion} (${written.map((entry) => `${entry.id}: ${entry.decision}`).join(", ")})`,
    existing,
    merged,
  );
}

function planChangesetChange(context: PublishContext): FileChange {
  const { cwd, manifest, written } = context;
  const lines = changesetLines(written);
  const path = `.changeset/${changesetName(written.map((entry) => entry.id))}.md`;
  const existing = readIfExists(cwd, path);
  return toChange(
    path,
    "release the dependency update and the VEX statements as a patch",
    existing,
    {
      content: renderChangeset(manifest.name, lines),
    },
  );
}

function toChange(
  path: string,
  reason: string,
  before: string | undefined,
  merged: { content: string } | { conflict: string },
): FileChange {
  if ("conflict" in merged) {
    return {
      path,
      action: "conflict",
      reason: `${path} ${merged.conflict}`,
      ...(before === undefined ? {} : { before }),
      after: before ?? "",
    };
  }
  return {
    path,
    action: fileAction(before, merged.content),
    reason,
    ...(before === undefined ? {} : { before }),
    after: merged.content,
  };
}

function readIfExists(cwd: string, path: string): string | undefined {
  return existsSync(join(cwd, path)) ? readFileSync(join(cwd, path), "utf8") : undefined;
}
