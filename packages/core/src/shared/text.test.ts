import { describe, expect, it } from "vitest";

import { canonicalJson } from "./hash.js";
import { compareStrings } from "./text.js";

describe("compareStrings", () => {
  it("orders by code unit, like the default sort", () => {
    const words = ["b", "B", "a", "ab", ""];
    expect(words.toSorted(compareStrings)).toEqual(words.toSorted());
    expect(compareStrings("a", "a")).toBe(0);
    expect(compareStrings("a", "b")).toBe(-1);
    expect(compareStrings("b", "a")).toBe(1);
  });
});

describe("canonicalJson", () => {
  it("sorts keys at every level and drops undefined members", () => {
    expect(canonicalJson({ b: 1, a: { d: [{ y: 2, x: undefined }], c: null } })).toBe(
      '{"a":{"c":null,"d":[{"y":2}]},"b":1}',
    );
  });

  it("serialises a bare undefined as null", () => {
    expect(canonicalJson(undefined)).toBe("null");
  });
});
