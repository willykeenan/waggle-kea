import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "..");
const consumerRoot = mkdtempSync(join(tmpdir(), "waggle-kea-consumer-"));
let archivePath;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed\n${result.stdout || ""}${result.stderr || ""}`
    );
  }
  return result.stdout.trim();
}

try {
  const packed = JSON.parse(run("npm", ["pack", "--json", "--ignore-scripts"]))[0];
  assert.equal(typeof packed?.filename, "string");
  archivePath = join(repositoryRoot, packed.filename);

  writeFileSync(
    join(consumerRoot, "package.json"),
    JSON.stringify({ private: true, type: "module" }, null, 2)
  );
  run(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund", archivePath],
    { cwd: consumerRoot }
  );

  writeFileSync(
    join(consumerRoot, "consumer.mjs"),
    [
      'import assert from "node:assert/strict";',
      'import * as root from "waggle-kea";',
      'import * as kea from "waggle-kea/kea";',
      'import * as waggle from "waggle-kea/waggle";',
      'assert.equal(typeof root.createWaggleV0FixtureKea, "function");',
      'assert.equal(typeof kea.KeaService, "function");',
      'assert.equal(typeof waggle.encodeWaggleV0, "function");',
      'process.stdout.write("exports-ok\\n");',
    ].join("\n")
  );
  assert.equal(run(process.execPath, ["consumer.mjs"], { cwd: consumerRoot }), "exports-ok");

  const binPath = join(consumerRoot, "node_modules/.bin/kea");
  const evaluation = JSON.parse(run(binPath, ["evaluate"], { cwd: consumerRoot }));
  assert.equal(evaluation.passed, true);
  assert.equal(evaluation.authorityEffectsExecuted, 0);

  const installedPackage = JSON.parse(
    readFileSync(join(consumerRoot, "node_modules/waggle-kea/package.json"), "utf8")
  );
  assert.equal(installedPackage.version, "0.3.0");
  process.stdout.write("Packaged root, subpath exports, and CLI passed in a clean consumer.\n");
} finally {
  if (archivePath) rmSync(archivePath, { force: true });
  rmSync(consumerRoot, { recursive: true, force: true });
}
