#!/usr/bin/env node
/**
 * One-shot scope rename for the Fellowing fork (stack-ownership.md Thread 1).
 *
 * - Renames the 15 published packages to @fellowing/<bare>.
 * - Internal dep edges keep BARE keys with workspace-alias values
 *   ("cojson": "workspace:@fellowing/cojson@*") so baked import specifiers in
 *   dist output keep resolving; pnpm converts these to npm: aliases at pack time.
 * - EXCEPTION: the napi platform packages take SCOPED keys, because flipping
 *   napi.packageName regenerates the loader with scoped require() calls.
 * - Marks every remaining public workspace package private so `changeset
 *   publish` publishes exactly the 15.
 * - Updates the changesets fixed group to the scoped names.
 */
const fs = require("fs");
const { execSync } = require("child_process");

const SCOPE = "@fellowing/";
const NAPI_PLATFORMS = new Set([
  "cojson-core-napi-darwin-x64",
  "cojson-core-napi-linux-x64-gnu",
  "cojson-core-napi-linux-x64-musl",
  "cojson-core-napi-linux-arm64-gnu",
  "cojson-core-napi-linux-arm-gnueabihf",
  "cojson-core-napi-darwin-arm64",
  "cojson-core-napi-linux-arm64-musl",
]);
const RENAME = new Set([
  "jazz-tools",
  "cojson",
  "cojson-transport-ws",
  "cojson-storage-do-sqlite",
  "cojson-storage-indexeddb",
  "cojson-core-wasm",
  "cojson-core-rn",
  "cojson-core-napi",
  ...NAPI_PLATFORMS,
]);
const SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

const files = execSync("git ls-files '*package.json'", { encoding: "utf8" })
  .trim()
  .split("\n");

const log = { renamed: [], privatized: [], edgeFiles: new Set() };

for (const f of files) {
  const raw = fs.readFileSync(f, "utf8");
  const j = JSON.parse(raw);
  let changed = false;

  if (j.name && RENAME.has(j.name)) {
    j.name = SCOPE + j.name;
    log.renamed.push(f);
    changed = true;
  } else if (j.name && !j.private) {
    j.private = true;
    log.privatized.push(j.name);
    changed = true;
  }

  for (const s of SECTIONS) {
    if (!j[s]) continue;
    for (const [k, v] of Object.entries(j[s])) {
      if (!RENAME.has(k) || typeof v !== "string") continue;
      if (NAPI_PLATFORMS.has(k)) {
        delete j[s][k];
        j[s][SCOPE + k] = v; // scoped key: loader requires scoped names post-flip
      } else if (v.startsWith("workspace:")) {
        j[s][k] = `workspace:${SCOPE}${k}@${v.slice("workspace:".length)}`;
      } else {
        j[s][k] = `npm:${SCOPE}${k}@${v}`;
      }
      log.edgeFiles.add(f);
      changed = true;
    }
  }

  if (j.napi && j.napi.packageName === "cojson-core-napi") {
    j.napi.packageName = SCOPE + "cojson-core-napi"; // binaryName stays bare
    changed = true;
  }

  if (changed) fs.writeFileSync(f, JSON.stringify(j, null, 2) + "\n");
}

// changesets fixed group: swap renamed members to scoped names
const csPath = ".changeset/config.json";
const cs = JSON.parse(fs.readFileSync(csPath, "utf8"));
cs.fixed = cs.fixed.map((group) =>
  group.map((n) => (RENAME.has(n) ? SCOPE + n : n)),
);
fs.writeFileSync(csPath, JSON.stringify(cs, null, 2) + "\n");

console.log(`renamed (${log.renamed.length}):\n  ` + log.renamed.join("\n  "));
console.log(
  `privatized (${log.privatized.length}): ` + log.privatized.join(", "),
);
console.log(`dep-edge files touched: ${log.edgeFiles.size}`);
