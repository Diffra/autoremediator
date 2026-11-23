import { beforeEach, describe, expect, it, vi } from "vitest";

import { UpstreamError } from "../../../shared/errors.js";

const mocked = vi.hoisted(() => ({
  queryOsvPackage: vi.fn(),
  fetchPackageVersions: vi.fn(),
}));

vi.mock("../sources/osv.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sources/osv.js")>()),
  queryOsvPackage: mocked.queryOsvPackage,
}));

vi.mock("../sources/registry.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sources/registry.js")>()),
  fetchPackageVersions: mocked.fetchPackageVersions,
}));

import { evaluatePackage } from "./index.js";

describe("evaluatePackage public SDK", () => {
  beforeEach(() => {
    mocked.queryOsvPackage.mockReset();
    mocked.fetchPackageVersions.mockReset();
    mocked.fetchPackageVersions.mockResolvedValue(["4.17.20", "4.17.21"]);
  });

  it("evaluates a package with no advisories as safe", async () => {
    mocked.queryOsvPackage.mockResolvedValue([]);

    const report = await evaluatePackage("lodash", {
      version: "4.17.21",
      enrichIntelligence: false,
    });

    expect(report.schemaVersion).toBe("1.0");
    expect(report.packageName).toBe("lodash");
    expect(report.evaluatedVersion).toBe("4.17.21");
    expect(report.isVulnerable).toBe(false);
    expect(report.verdict).toBe("safe");
    expect(report.latestVersion).toBe("4.17.21");
  });

  it("reports a vulnerable version from the advisories OSV returns", async () => {
    mocked.queryOsvPackage.mockResolvedValue([
      {
        id: "GHSA-35jh-r3h4-6jhm",
        aliases: ["CVE-2021-23337"],
        summary: "Command injection in lodash",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/7.5" }],
        affected: [
          {
            package: { ecosystem: "npm", name: "lodash" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
          },
        ],
      },
    ]);

    const report = await evaluatePackage("lodash", {
      version: "4.17.20",
      enrichIntelligence: false,
    });

    expect(report.isVulnerable).toBe(true);
    expect(report.verdict).toBe("vulnerable");
    expect(report.vulnerabilities).toHaveLength(1);
  });

  it("fails loudly when OSV cannot be reached instead of calling the package safe", async () => {
    mocked.queryOsvPackage.mockRejectedValue(new Error("getaddrinfo ENOTFOUND api.osv.dev"));

    const attempt = evaluatePackage("lodash", { version: "4.17.20", enrichIntelligence: false });

    await expect(attempt).rejects.toBeInstanceOf(UpstreamError);
    await expect(attempt).rejects.toThrow(/OSV/);
  });

  it.each(["", "lodash; echo pwned", "../escape", "@scope/", "-flag"])(
    "rejects %j as a package name before any lookup",
    async (name) => {
      await expect(evaluatePackage(name, { enrichIntelligence: false })).rejects.toThrow(
        /not a valid npm package name/,
      );
      expect(mocked.queryOsvPackage).not.toHaveBeenCalled();
    },
  );
});
