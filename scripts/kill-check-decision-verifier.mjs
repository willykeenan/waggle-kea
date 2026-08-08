#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const target = resolve("scripts/verify-decision-sufficiency.mjs");
const result = spawnSync(process.execPath, [target, "--self-test"], {
  cwd: process.cwd(),
  encoding: "utf8",
  timeout: 30_000,
});
if (result.status !== 0 || !result.stdout.split("\n").includes("VERIFIER_SELF_TEST_OK")) {
  process.stderr.write(`${result.stdout}${result.stderr}`);
  process.exit(1);
}
console.log("LANE_OK decision-verifier");
