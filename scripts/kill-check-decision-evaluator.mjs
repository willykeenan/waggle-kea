#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const target = resolve("benchmarks/decision-sufficiency/evaluate.ts");
const result = spawnSync("npx", ["tsx", target, "--self-test"], {
  cwd: process.cwd(),
  encoding: "utf8",
  timeout: 60_000,
});
if (result.status !== 0 || !result.stdout.split("\n").includes("EVALUATOR_SELF_TEST_OK")) {
  process.stderr.write(`${result.stdout}${result.stderr}`);
  process.exit(1);
}
console.log("LANE_OK decision-evaluator");
