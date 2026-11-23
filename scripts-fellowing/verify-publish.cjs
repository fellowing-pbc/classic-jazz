#!/usr/bin/env node
/**
 * Post-publish gate: `pnpm -r publish` skips packages whose version already
 * exists on the registry and exits green, so a fully-republished version is
 * otherwise a silent no-op run. Reads the pnpm-publish-summary.json that
 * `pnpm -r publish --report-summary` writes, which lists only the packages it
 * actually published, and fails unless every publishable package is there at
 * the given version. It never asks the registry: propagation there can lag
 * the publish by far longer than a job should wait.
 *
 * Usage: node scripts-fellowing/verify-publish.cjs 0.20.19-fellowing.0
 */
const fs = require("fs");
const { execSync } = require("child_process");

const SUMMARY = "pnpm-publish-summary.json";

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

if (!fs.existsSync(SUMMARY)) {
  console.error(`${SUMMARY} not found: run pnpm -r publish --report-summary`);
  process.exit(1);
}

const published = new Set(
  JSON.parse(fs.readFileSync(SUMMARY, "utf8")).publishedPackages.map(
    (p) => `${p.name}@${p.version}`,
  ),
);
const missing = names.filter((name) => !published.has(`${name}@${version}`));

if (missing.length > 0) {
  console.error(`not published at ${version}: ${missing.join(", ")}`);
  process.exit(1);
}
console.log(`all ${names.length} packages published at ${version}`);
