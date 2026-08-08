#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const output = resolve("benchmarks/decision-sufficiency/results/local-v1");
const localPython = resolve("benchmarks/banking77/.venv/bin/python");
const python = process.env.DECISION_PYTHON || (existsSync(localPython) ? localPython : "python3");
const offline = process.argv.includes("--offline");

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit", timeout: 15 * 60_000 });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

rmSync(output, { recursive: true, force: true });
run(python, [
  "benchmarks/decision-sufficiency/run.py",
  ...(offline ? ["--offline"] : []),
  "--output",
  output,
]);
run("npx", [
  "tsx",
  "benchmarks/decision-sufficiency/evaluate.ts",
  "--input",
  output,
  "--output",
  output,
]);
run(process.execPath, ["scripts/verify-decision-sufficiency.mjs", "--results", output]);
run(process.execPath, ["scripts/verify-decision-consumer.mjs", "--results", output]);
