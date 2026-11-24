import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * The file and function length rules in `.oxlintrc.json` apply to all production code. The only
 * place they may be switched off is for test files, which are long by nature. A per-file list of
 * exceptions would let new violations in, so none is allowed.
 */
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "..");
const SIZE_RULES = ["eslint/max-lines", "eslint/max-lines-per-function"];
const TEST_FILE = /(?:\.test\.|\.spec\.|\/tests?\/|\/__tests__\/|\/testing\/)/;

interface Override {
  files: string[];
  rules: Record<string, unknown>;
}

function overrides(): Override[] {
  const text = readFileSync(join(root, ".oxlintrc.json"), "utf8").replaceAll(/^\s*\/\/.*$/gm, "");
  return (JSON.parse(text) as { overrides: Override[] }).overrides;
}

describe("size limits", () => {
  it("are switched off only for test files", () => {
    const offenders = overrides()
      .filter((override) => SIZE_RULES.some((rule) => rule in override.rules))
      .flatMap((override) => override.files)
      .filter((pattern) => !TEST_FILE.test(pattern.replaceAll("**", "x").replace(/^\*/, "/")));
    expect(offenders).toEqual([]);
  });

  it("are enforced for production code", () => {
    const text = readFileSync(join(root, ".oxlintrc.json"), "utf8");
    for (const rule of SIZE_RULES) expect(text).toContain(`"${rule}": [`);
  });
});
