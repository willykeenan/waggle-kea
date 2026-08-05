#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const base = process.env.WAGGLE_KEA_SERVER_LANE_BASE ||
  "f067d1ed9457fc6cf2e5ef82a30a7a48c84fbde1";
const allowed = [
  "scripts/verify-server-lane.mjs",
  "src/kea/server.ts",
  "tests/server-boundaries.test.ts",
];

function run(command, args, options = {}) {
  const output = execFileSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: options.stdio || "pipe",
  });
  return typeof output === "string" ? output.trim() : "";
}

const mergeBase = run("git", ["merge-base", "HEAD", base]);
assert.equal(mergeBase, base, `lane must descend directly from ${base}`);

const changed = run("git", ["diff", "--name-only", base, "--"])
  .split("\n")
  .filter(Boolean);
const untracked = run("git", ["ls-files", "--others", "--exclude-standard"])
  .split("\n")
  .filter(Boolean);
const actual = [...new Set([...changed, ...untracked])].sort();
assert.deepEqual(actual, [...allowed].sort(), "lane changed files outside its ownership boundary");

const tsx = resolve("node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");
assert.equal(existsSync(tsx), true, "run npm ci before the lane verifier");

run(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "typecheck"], {
  stdio: "inherit",
});
run(tsx, ["--test", "tests/server-boundaries.test.ts"], { stdio: "inherit" });

process.stdout.write(
  `${JSON.stringify({
    ok: true,
    base,
    files: actual,
    checks: ["scope", "typecheck", "server-boundaries"],
  })}\n`
);
