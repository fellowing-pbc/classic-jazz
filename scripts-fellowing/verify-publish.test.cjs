// Run with: node --test scripts-fellowing/
const assert = require("node:assert/strict");
const { spawnSync, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const SCRIPT = path.join(__dirname, "verify-publish.cjs");
const VERSION = "0.20.19-fellowing.6";
const PACKAGES = Array.from(
  { length: 15 },
  (_, i) => `@fellowing/pkg-${i + 1}`,
);

// A workspace with the 15 publishable packages and a private one, plus `npm`
// and `sleep` stubs on PATH. The npm stub logs each call and answers as a
// lagging registry: it never has `laggingPackage`.
function workspace({ published, laggingPackage = PACKAGES[2] }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-publish-"));
  const write = (file, json) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), JSON.stringify(json));
  };
  write("package.json", { name: "root", private: true });
  PACKAGES.forEach((name, i) => {
    write(`packages/pkg-${i + 1}/package.json`, { name, version: VERSION });
  });
  write("packages/internal/package.json", {
    name: "@fellowing/internal",
    private: true,
  });
  if (published) {
    write("pnpm-publish-summary.json", { publishedPackages: published });
  }
  execFileSync("git", ["init", "-q"], { cwd: dir });
  execFileSync("git", ["add", "."], { cwd: dir });

  const bin = path.join(dir, ".bin");
  fs.mkdirSync(bin);
  const npmLog = path.join(dir, "npm-calls.log");
  fs.writeFileSync(
    path.join(bin, "npm"),
    `#!/bin/sh\necho "$@" >> "${npmLog}"\ncase "$2" in ${laggingPackage}@*) exit 1;; esac\necho ${VERSION}\n`,
    { mode: 0o755 },
  );
  fs.writeFileSync(path.join(bin, "sleep"), "#!/bin/sh\n", { mode: 0o755 });

  const run = () =>
    spawnSync("node", [SCRIPT, VERSION], {
      cwd: dir,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
    });
  const npmCalls = () =>
    fs.existsSync(npmLog) ? fs.readFileSync(npmLog, "utf8") : "";
  return { run, npmCalls };
}

const all = PACKAGES.map((name) => ({ name, version: VERSION }));

test("passes when all 15 published, while the registry lags", () => {
  const ws = workspace({ published: all });
  const result = ws.run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(ws.npmCalls(), "");
});

test("fails and names a package missing from the summary", () => {
  const ws = workspace({
    published: all.filter((p) => p.name !== "@fellowing/pkg-7"),
    laggingPackage: "none",
  });
  const result = ws.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /@fellowing\/pkg-7\b/);
  assert.doesNotMatch(result.stderr, /@fellowing\/pkg-1\b/);
});

test("fails and names a package published at another version", () => {
  const ws = workspace({
    published: all.map((p) =>
      p.name === "@fellowing/pkg-11"
        ? { ...p, version: "0.20.19-fellowing.5" }
        : p,
    ),
    laggingPackage: "none",
  });
  const result = ws.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /@fellowing\/pkg-11\b/);
});

test("fails when pnpm wrote no summary", () => {
  const ws = workspace({ published: null, laggingPackage: "none" });
  const result = ws.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /pnpm-publish-summary\.json/);
});
