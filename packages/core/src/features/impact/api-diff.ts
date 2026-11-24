/**
 * Compare the public API surface of two versions of a package and list what a consumer could
 * trip over: removed or renamed exports and members, changed signatures, changed types.
 *
 * Severity is deliberately coarse. `breaking` is a change that makes an existing, correct use fail
 * (a removed export, a new required argument). `possibly-breaking` is a change that may or may not
 * matter to a given caller (a type text that changed, which could be a widening). The text of both
 * sides is always kept so the reader can judge.
 */
import type { ApiMember, ApiSurface, ApiSymbol } from "./dts-surface.js";
import { compareSignatures } from "./signature-diff.js";

export type ChangeSeverity = "breaking" | "possibly-breaking";

export type ApiChangeCategory =
  | "removed-export"
  | "renamed-export"
  | "kind-changed"
  | "signature-changed"
  | "type-changed"
  | "removed-member"
  | "renamed-member"
  | "member-changed"
  | "added-required-member"
  | "extends-changed";

export interface ApiChange {
  specifier: string;
  /** Export name (`default` for a default export). */
  symbol: string;
  /** Member key within the symbol, when the change is to a member. */
  member?: string;
  /** Class, interface or namespace members versus the export itself. */
  memberOf?: "class" | "interface" | "namespace" | "enum" | "object";
  category: ApiChangeCategory;
  severity: ChangeSeverity;
  /** What changed, in one sentence. */
  reason: string;
  before?: string;
  after?: string;
  /** New call shape for a function, for checking call sites. */
  arity?: { min: number; max: number };
  /** New name, for a rename. */
  renamedTo?: string;
}

function shapeOf(symbol: ApiSymbol): string {
  if (symbol.kind === "function") {
    return `function:${symbol.signatures
      .map((s) => s.text)
      .toSorted()
      .join("|")}`;
  }
  if (
    symbol.kind === "class" ||
    symbol.kind === "interface" ||
    symbol.kind === "namespace" ||
    symbol.kind === "enum"
  ) {
    return `${symbol.kind}:${[...symbol.members.values()]
      .map((m) => `${m.key}/${m.kind}/${m.signatures.map((s) => s.text).join(",")}/${m.type ?? ""}`)
      .toSorted()
      .join(";")}`;
  }
  return `${symbol.kind}:${symbol.type ?? ""}`;
}

function memberShape(member: ApiMember): string {
  return `${member.kind}/${member.optional}/${member.signatures.map((signature) => signature.text).join(",")}/${member.type ?? ""}`;
}

/** Where a member change sits: the export, the member and what contains it. */
interface MemberSite {
  specifier: string;
  symbol: string;
  memberOf: ApiChange["memberOf"];
}

function memberSite(specifier: string, name: string, kind: ApiSymbol["kind"]): MemberSite {
  return { specifier, symbol: name, memberOf: memberContainerOf(kind) };
}

/** Members that are gone: a probable rename when an added member has the same shape. */
function removedMemberChanges(
  site: MemberSite,
  removed: ApiMember[],
  added: ApiMember[],
  claimed: Set<string>,
): ApiChange[] {
  const changes: ApiChange[] = [];
  for (const member of removed) {
    const twin = added.find(
      (candidate) =>
        !claimed.has(candidate.key) &&
        memberShape(candidate) === memberShape(member) &&
        candidate.static === member.static,
    );
    if (twin) {
      claimed.add(twin.key);
      changes.push({
        ...site,
        member: member.key,
        category: "renamed-member",
        severity: "breaking",
        reason: `\`${member.name}\` is gone; \`${twin.name}\` has the same shape (probable rename)`,
        renamedTo: twin.name,
      });
    } else {
      changes.push({
        ...site,
        member: member.key,
        category: "removed-member",
        severity: "breaking",
        reason: `member \`${member.name}\` was removed`,
        before: member.signatures[0]?.text ?? member.type,
      });
    }
  }
  return changes;
}

/** What changed about a member that exists on both sides. */
function keptMemberChanges(
  site: MemberSite,
  member: ApiMember,
  next: ApiMember,
  typed: boolean,
): ApiChange[] {
  const at = { ...site, member: member.key, category: "member-changed" as const };
  if (member.kind !== next.kind) {
    return [
      {
        ...at,
        severity: "breaking",
        reason: `member \`${member.name}\` changed from ${member.kind} to ${next.kind}`,
      },
    ];
  }
  const changes: ApiChange[] = [];
  for (const finding of compareSignatures(member.signatures, next.signatures, typed)) {
    changes.push({ ...at, ...finding, category: "member-changed" });
  }
  if (member.type !== undefined && next.type !== undefined && member.type !== next.type) {
    changes.push({
      ...at,
      severity: "possibly-breaking",
      reason: `type of \`${member.name}\` changed (${member.type} -> ${next.type})`,
      before: member.type,
      after: next.type,
    });
  }
  if (member.optional !== next.optional) {
    changes.push({
      ...at,
      severity: "possibly-breaking",
      reason: next.optional
        ? `\`${member.name}\` became optional (may now be undefined)`
        : `\`${member.name}\` became required`,
    });
  }
  if (!member.readonly && next.readonly) {
    changes.push({
      ...at,
      severity: "possibly-breaking",
      reason: `\`${member.name}\` became readonly`,
    });
  }
  return changes;
}

function memberChanges(
  specifier: string,
  name: string,
  before: ApiSymbol,
  after: ApiSymbol,
  typed: boolean,
): ApiChange[] {
  const site = memberSite(specifier, name, before.kind);
  const removed = [...before.members.values()].filter((member) => !after.members.has(member.key));
  const added = [...after.members.values()].filter((member) => !before.members.has(member.key));
  const claimed = new Set<string>();

  const changes = removedMemberChanges(site, removed, added, claimed);
  for (const member of before.members.values()) {
    const next = after.members.get(member.key);
    if (next) changes.push(...keptMemberChanges(site, member, next, typed));
  }
  if (before.kind === "interface") {
    for (const member of added) {
      if (claimed.has(member.key) || member.optional || member.kind === "index") continue;
      changes.push({
        ...site,
        member: member.key,
        category: "added-required-member",
        severity: "possibly-breaking",
        reason: `new required member \`${member.name}\` (breaks code that implements or constructs this interface)`,
      });
    }
  }
  return changes;
}

function typeLike(kind: string): boolean {
  return kind === "interface" || kind === "type";
}

/** Compare one exported symbol. */
function compareSymbol(
  specifier: string,
  name: string,
  before: ApiSymbol,
  after: ApiSymbol,
  typed: boolean,
): ApiChange[] {
  const changes: ApiChange[] = [];
  if (before.kind !== after.kind) {
    changes.push({
      specifier,
      symbol: name,
      category: "kind-changed",
      severity: typeLike(before.kind) && typeLike(after.kind) ? "possibly-breaking" : "breaking",
      reason: `export changed from ${before.kind} to ${after.kind}`,
      before: before.kind,
      after: after.kind,
    });
    return changes;
  }
  if (before.kind === "function") {
    for (const finding of compareSignatures(before.signatures, after.signatures, typed)) {
      changes.push({ specifier, symbol: name, ...finding });
    }
  }
  const hasMembers = before.members.size > 0 || after.members.size > 0;
  if (
    before.kind === "class" ||
    before.kind === "interface" ||
    before.kind === "namespace" ||
    before.kind === "enum" ||
    (before.kind === "variable" && hasMembers)
  ) {
    changes.push(...memberChanges(specifier, name, before, after, typed));
    if ((before.extends ?? "") !== (after.extends ?? "")) {
      changes.push({
        specifier,
        symbol: name,
        category: "extends-changed",
        severity: "possibly-breaking",
        reason: `base type changed (${before.extends ?? "none"} -> ${after.extends ?? "none"})`,
        before: before.extends,
        after: after.extends,
      });
    }
  }
  if (
    (before.kind === "type" || before.kind === "variable") &&
    before.type !== undefined &&
    after.type !== undefined &&
    before.type !== after.type
  ) {
    changes.push({
      specifier,
      symbol: name,
      category: "type-changed",
      severity: "possibly-breaking",
      reason: `${before.kind === "type" ? "type definition" : "variable type"} changed`,
      before: before.type,
      after: after.type,
    });
  }
  return changes;
}

/** Changes between two surfaces of the same entry point. */
export function compareSurfaces(
  specifier: string,
  before: ApiSurface,
  after: ApiSurface,
): ApiChange[] {
  const typed = before.source === "types" && after.source === "types";
  const changes: ApiChange[] = [];
  const removed = [...before.symbols.values()].filter((symbol) => !after.symbols.has(symbol.name));
  const added = [...after.symbols.values()].filter((symbol) => !before.symbols.has(symbol.name));
  const claimed = new Set<string>();

  for (const symbol of removed) {
    const twin = added.find(
      (candidate) =>
        !claimed.has(candidate.name) &&
        candidate.kind === symbol.kind &&
        shapeOf(candidate) === shapeOf(symbol),
    );
    if (twin && symbol.name !== "default") {
      claimed.add(twin.name);
      changes.push({
        specifier,
        symbol: symbol.name,
        category: "renamed-export",
        severity: "breaking",
        reason: `\`${symbol.name}\` is gone; \`${twin.name}\` has the same shape (probable rename)`,
        renamedTo: twin.name,
      });
    } else {
      changes.push({
        specifier,
        symbol: symbol.name,
        category: "removed-export",
        severity: "breaking",
        reason: `\`${symbol.name}\` is no longer exported`,
        before: symbol.signatures[0]?.text ?? symbol.type ?? symbol.kind,
      });
    }
  }
  for (const symbol of before.symbols.values()) {
    const next = after.symbols.get(symbol.name);
    if (next) changes.push(...compareSymbol(specifier, symbol.name, symbol, next, typed));
  }
  return changes;
}

/** What a changed member belongs to, in the words a report uses; undefined for kinds with no members. */
function memberContainerOf(kind: ApiSymbol["kind"]): ApiChange["memberOf"] {
  if (kind === "variable") {
    return "object";
  }
  if (kind === "class" || kind === "interface" || kind === "namespace" || kind === "enum") {
    return kind;
  }
  return undefined;
}
