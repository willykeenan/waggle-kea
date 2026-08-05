#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const base = "f067d1ed9457fc6cf2e5ef82a30a7a48c84fbde1";
const allowed = new Set([
  "scripts/verify-protocol-integrity.mjs",
  "src/index.ts",
  "src/kea/index.ts",
  "src/kea/ledger.ts",
  "src/kea/service.ts",
  "src/kea/types.ts",
  "src/kea/validation.ts",
  "src/waggle/codec.ts",
  "tests/protocol-integrity.test.ts",
]);

function run(command, args, capture = false) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
  });
  if (result.status !== 0) {
    if (capture) process.stderr.write(result.stderr || result.stdout || "");
    process.exit(result.status ?? 1);
  }
  return capture ? result.stdout.trim() : "";
}

const trackedChanges = run("git", ["diff", "--name-only", base, "--"], true)
  .split("\n")
  .filter(Boolean);
const untrackedChanges = run(
  "git",
  ["ls-files", "--others", "--exclude-standard"],
  true
)
  .split("\n")
  .filter(Boolean);
const changed = [...new Set([...trackedChanges, ...untrackedChanges])].sort();
const outsideLane = changed.filter((path) => !allowed.has(path));
if (outsideLane.length) {
  process.stderr.write(`protocol-integrity lane escaped its allowlist: ${outsideLane.join(", ")}\n`);
  process.exit(1);
}

run("npm", ["exec", "--", "tsx", "--test", "tests/protocol-integrity.test.ts"]);
run("npm", ["run", "check"]);

process.stdout.write(
  `${JSON.stringify(
    {
      ok: true,
      base,
      changed,
      focusedTest: "tests/protocol-integrity.test.ts",
      fullCheck: "npm run check",
    },
    null,
    2
  )}\n`
);
