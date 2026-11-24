import { describe, expect, it } from "vitest";

import { fileAction } from "./file-action.js";

describe("fileAction", () => {
  it("creates a file that does not exist yet", () => {
    expect(fileAction(undefined, "new")).toBe("create");
  });

  it("leaves a file whose content already matches", () => {
    expect(fileAction("same", "same")).toBe("unchanged");
  });

  it("updates a file whose content differs, including an empty one", () => {
    expect(fileAction("old", "new")).toBe("update");
    expect(fileAction("", "new")).toBe("update");
  });
});
