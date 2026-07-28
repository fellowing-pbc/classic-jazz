#!/usr/bin/env node
/**
 * Post-publish gate: `pnpm -r publish` skips packages whose version already
 * exists on the registry and exits green, so a fully-republished version is
 * otherwise a silent no-op run. Confirms the registry serves every published
 * package at the given version, with retries for propagation lag.
 *
 * Usage: node scripts-fellowing/verify-publish.cjs 0.20.19-fellowing.0
 */
const fs = require("fs");
const { execSync, execFileSync } = require("child_process");

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+-fellowing\.\d+$/.test(version)) {
  console.error(
    "usage: verify-publish.cjs <jazz-base>-fellowing.<N>  e.g. 0.20.19-fellowing.0",
  );
  process.exit(1);
}

const names = execSync("git ls-files '*package.json'", { encoding: "utf8" })
  .trim()
  .split("\n")
  .map((f) => JSON.parse(fs.readFileSync(f, "utf8")))
  .filter((j) => j.name && j.name.startsWith("@fellowing/") && !j.private)
  .map((j) => j.name);

if (names.length !== 15) {
  console.error(
    `expected exactly 15 publishable packages, found ${names.length}`,
  );
  process.exit(1);
}

const ATTEMPTS = 5;
const DELAY_SECONDS = 15;
let missing = names;
for (let attempt = 1; attempt <= ATTEMPTS && missing.length > 0; attempt++) {
  if (attempt > 1) execFileSync("sleep", [String(DELAY_SECONDS)]);
  missing = missing.filter((name) => {
    try {
      execFileSync("npm", ["view", `${name}@${version}`, "version"], {
        stdio: "pipe",
      });
      return false;
    } catch {
      return true;
    }
  });
  console.log(
    `attempt ${attempt}: ${names.length - missing.length}/${names.length} live on registry`,
  );
}

if (missing.length > 0) {
  console.error(`not on registry at ${version}: ${missing.join(", ")}`);
  process.exit(1);
}
console.log(`all ${names.length} packages live at ${version}`);
