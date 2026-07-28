#!/usr/bin/env node
/**
 * Stamp the fork's release version across the 15 published packages.
 *
 * Usage: node scripts-fellowing/set-version.cjs 0.20.19-fellowing.0
 *
 * Scheme (docs/plans/stack-ownership.md): <jazz-base>-fellowing.N, where the
 * base always matches the upstream release this tree carries. All 15 packages
 * version in lockstep (the napi loader's baked version check requires it).
 *
 * Also:
 * - ensures publishConfig.access=public on every @fellowing/* package
 *   (scoped packages default to restricted on publish)
 * - stamps the repository field (fork URL + per-package directory) — trusted
 *   publishing's provenance validation rejects a mismatched repository.url,
 *   and upstream merges can reintroduce garden-co URLs
 * - normalizes any pinned workspace ranges pointing at @fellowing/* packages
 *   to `@*` — a pin like `workspace:@fellowing/cojson@0.20.19` stops
 *   resolving once the workspace version is a prerelease
 */
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPOSITORY_URL = "git+https://github.com/fellowing-pbc/classic-jazz.git";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+-fellowing\.\d+$/.test(version)) {
  console.error(
    "usage: set-version.cjs <jazz-base>-fellowing.<N>  e.g. 0.20.19-fellowing.0",
  );
  process.exit(1);
}

// The tree carries the upstream jazz base it forked from; a version claiming
// a different base would publish 15 immutable packages advertising an
// upstream release this tree does not contain.
const anchor = JSON.parse(
  fs.readFileSync("packages/cojson/package.json", "utf8"),
);
const treeBase = anchor.version.replace(/-fellowing\.\d+$/, "");
if (!version.startsWith(`${treeBase}-fellowing.`)) {
  console.error(
    `version base mismatch: tree carries ${treeBase} (packages/cojson), got ${version}`,
  );
  process.exit(1);
}

const files = execSync("git ls-files '*package.json'", { encoding: "utf8" })
  .trim()
  .split("\n");
const SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

let stamped = 0;
let normalized = 0;
for (const f of files) {
  const j = JSON.parse(fs.readFileSync(f, "utf8"));
  let changed = false;

  if (j.name && j.name.startsWith("@fellowing/")) {
    j.version = version;
    j.publishConfig = { ...(j.publishConfig || {}), access: "public" };
    j.repository = {
      type: "git",
      url: REPOSITORY_URL,
      directory: path.dirname(f),
    };
    stamped++;
    changed = true;
  }

  for (const s of SECTIONS) {
    if (!j[s]) continue;
    for (const [k, v] of Object.entries(j[s])) {
      if (typeof v !== "string") continue;
      const m = v.match(/^workspace:(@fellowing\/[^@]+)@(.+)$/);
      if (m && m[2] !== "*") {
        j[s][k] = `workspace:${m[1]}@*`;
        normalized++;
        changed = true;
      }
    }
  }

  if (changed) fs.writeFileSync(f, JSON.stringify(j, null, 2) + "\n");
}

console.log(
  `stamped ${stamped} packages at ${version}; normalized ${normalized} pinned workspace ranges`,
);
if (stamped !== 15) {
  console.error(
    `expected exactly 15 @fellowing/* packages, stamped ${stamped}`,
  );
  process.exit(1);
}
