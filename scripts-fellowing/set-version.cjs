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
 * - normalizes any pinned workspace ranges pointing at @fellowing/* packages
 *   to `@*` — a pin like `workspace:@fellowing/cojson@0.20.19` stops
 *   resolving once the workspace version is a prerelease
 */
const fs = require("fs");
const { execSync } = require("child_process");

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+-fellowing\.\d+$/.test(version)) {
  console.error(
    "usage: set-version.cjs <jazz-base>-fellowing.<N>  e.g. 0.20.19-fellowing.0",
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
