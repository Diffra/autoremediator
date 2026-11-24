/** Which newer release radar compares an installed version with. */
import semver from "semver";

/** The release to compare with, or undefined when the installed version is not behind it. */
export function pickTarget(
  installed: string,
  stable: readonly string[],
  latest: string | undefined,
  target: "latest" | "minor" | "patch",
): string | undefined {
  const newer = stable.filter((version) => semver.gt(version, installed));
  const candidates = newer.filter(
    (version) =>
      target === "latest" ||
      (semver.major(version) === semver.major(installed) &&
        (target === "minor" || semver.minor(version) === semver.minor(installed))),
  );
  if (target === "latest" && latest && candidates.includes(latest)) return latest;
  return candidates.toSorted((a, b) => semver.compare(a, b)).at(-1);
}
