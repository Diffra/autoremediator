import { isMap, isNode, isSeq, parseDocument, type Document, type YAMLSeq } from "yaml";

import { isRecord } from "../../shared/guards.js";
import type { PolicyPatch } from "./proposal.js";
import { sanitizeNote } from "./sanitize.js";

/** Largest suppression a patch may add, in days from now. A model cannot make one permanent. */
export const MAX_SUPPRESSION_DAYS = 366;

/** Thrown when a patch asks for something the deterministic checks refuse. */
export class PolicyPatchError extends Error {
  override readonly name = "PolicyPatchError";
}

type Path = (string | number)[];

/** Plain JS value at a path, or undefined. */
function read(doc: Document, path: Path): unknown {
  const node = doc.getIn(path, true);
  if (isNode(node)) return node.toJSON();
  return node;
}

/** Every `[path, value]` leaf of a nested object; arrays count as leaves. */
function leaves(prefix: Path, value: unknown): [Path, unknown][] {
  if (!isRecord(value)) return [[prefix, value]];
  return Object.entries(value).flatMap(([key, child]) => leaves([...prefix, key], child));
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export interface ApplyContext {
  now: Date;
}

export interface ApplyResult {
  /** The new file text. Identical to the old text when the patch changed nothing. */
  text: string;
  /** Number of edits that changed a value. Zero means the patch was already in place. */
  edits: number;
}

function validateSuppressionDate(value: string, now: Date, cveId: string): string {
  const time = new Date(value).getTime();
  if (Number.isNaN(time)) {
    throw new PolicyPatchError(`The suppression for ${cveId} has an invalid expiry "${value}".`);
  }
  if (time <= now.getTime()) {
    throw new PolicyPatchError(`The suppression for ${cveId} expires in the past (${value}).`);
  }
  if (time > now.getTime() + MAX_SUPPRESSION_DAYS * 86_400_000) {
    throw new PolicyPatchError(
      `The suppression for ${cveId} would last more than ${MAX_SUPPRESSION_DAYS} days (${value}). Suppressions must expire within a year.`,
    );
  }
  return value;
}

function ensureSeq(doc: Document, key: string): YAMLSeq | undefined {
  const node = doc.get(key, true);
  if (isSeq(node)) return node;
  return undefined;
}

/**
 * Apply a patch to the policy file's text with the YAML Document API, so comments, key order and
 * untouched formatting survive. Values equal to what is already there are skipped, which makes
 * applying the same patch twice a no-op. The caller validates the result with `loadPolicy`.
 */
export function applyPatch(
  before: string | undefined,
  patch: PolicyPatch,
  context: ApplyContext,
): ApplyResult {
  const source = before ?? "";
  const doc: Document = parseDocument(source);
  if (doc.errors.length > 0) {
    throw new PolicyPatchError(`The current policy is not valid YAML: ${doc.errors[0]?.message}`);
  }
  doc.contents ??= doc.createNode({});
  if (!isMap(doc.contents)) {
    throw new PolicyPatchError("The current policy is not a YAML mapping.");
  }

  let edits = 0;
  const setLeaf = (path: Path, value: unknown): void => {
    edits += setLeafIn(doc, path, value);
  };

  if (patch.allowMajorBumps !== undefined) setLeaf(["allowMajorBumps"], patch.allowMajorBumps);
  if (patch.containmentMode !== undefined) setLeaf(["containmentMode"], patch.containmentMode);

  for (const key of ["denyPackages", "allowPackages"] as const) {
    const edit = patch[key];
    if (edit) edits += editPackageList(doc, key, edit);
  }

  for (const key of [
    "constraints",
    "exploitSignalOverride",
    "sla",
    "dispositionPolicy",
    "escalationGraph",
    "autonomy",
  ] as const) {
    const value = patch[key];
    if (value === undefined) continue;
    for (const [path, leaf] of leaves([key], value)) {
      if (leaf === undefined) continue;
      if (isRecord(leaf)) continue; // an empty object sets nothing
      setLeaf(path, leaf);
    }
  }

  for (const proposed of patch.suppressions ?? []) {
    edits += applySuppression(doc, proposed, context.now);
  }

  if (edits === 0) return { text: source, edits };
  return { text: doc.toString({ lineWidth: 0 }), edits };
}

/** Sets a value unless the document already holds it; returns how many edits that made. */
function setLeafIn(doc: Document, path: Path, value: unknown): number {
  if (sameJson(read(doc, path), value)) {
    return 0;
  }
  doc.setIn(path, value);
  return 1;
}

type PackageListEdit = NonNullable<PolicyPatch["denyPackages"]>;

/** Adds to and removes from `denyPackages` or `allowPackages`, keeping comments on other entries. */
function editPackageList(
  doc: Document,
  key: "denyPackages" | "allowPackages",
  edit: PackageListEdit,
): number {
  const current = (read(doc, [key]) as string[] | undefined) ?? [];
  const removals = new Set(edit.remove ?? []);
  const survivors = current.filter((entry) => !removals.has(entry));
  const additions = [...new Set(edit.add ?? [])].filter((entry) => !survivors.includes(entry));
  const wanted = [...survivors, ...additions];
  if (sameJson(current, wanted)) {
    return 0;
  }

  const seq = ensureSeq(doc, key);
  if (!seq) {
    doc.setIn([key], wanted);
    return 1;
  }
  // Edit in place so comments on the other entries stay where they are.
  for (let index = seq.items.length - 1; index >= 0; index -= 1) {
    const item = seq.items[index];
    const value = isNode(item) ? (item as { value?: unknown }).value : item;
    if (typeof value === "string" && removals.has(value)) seq.delete(index);
  }
  for (const entry of additions) seq.add(doc.createNode(entry));
  return 1;
}

type ProposedSuppression = NonNullable<PolicyPatch["suppressions"]>[number];

/** Adds a suppression, or updates the fields of the one that already covers the same CVE. */
function applySuppression(
  doc: Document,
  proposed: ProposedSuppression,
  now: ApplyContext["now"],
): number {
  const cveId = /^cve-/i.test(proposed.cveId)
    ? proposed.cveId.toUpperCase()
    : proposed.cveId.toLowerCase();
  const entry: Record<string, unknown> = {
    cveId,
    justification: proposed.justification,
    ...(proposed.notes ? { notes: sanitizeNote(proposed.notes) } : {}),
    expiresAt: validateSuppressionDate(proposed.expiresAt, now, cveId),
  };
  if (entry["notes"] === "") delete entry["notes"];

  const existing = ensureSeq(doc, "suppressions");
  if (!existing) {
    doc.setIn(["suppressions"], [entry]);
    return 1;
  }
  const index = existing.items.findIndex((item) => {
    const json = isNode(item) ? item.toJSON() : item;
    return isRecord(json) && String(json["cveId"]).toUpperCase() === cveId.toUpperCase();
  });
  if (index === -1) {
    existing.add(doc.createNode(entry));
    return 1;
  }
  let edits = 0;
  for (const [field, value] of Object.entries(entry)) {
    edits += setLeafIn(doc, ["suppressions", index, field], value);
  }
  return edits;
}
