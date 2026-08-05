#!/usr/bin/env node

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "..");
const benchmarkRoot = resolve(repositoryRoot, "benchmarks/banking77");
const virtualEnvironment = resolve(benchmarkRoot, ".venv");
const localResults = resolve(benchmarkRoot, "results/local-v1");
const forwarded = process.argv.slice(2);

if (forwarded.some((argument) => argument !== "--offline")) {
  throw new Error("benchmark:banking77 accepts only the optional --offline flag");
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    stdio: "inherit",
    env: { ...process.env, PIP_DISABLE_PIP_VERSION_CHECK: "1" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with ${result.status ?? result.signal}`);
  }
}

function availablePython() {
  for (const candidate of ["python3", "python"]) {
    const result = spawnSync(candidate, ["--version"], { stdio: "ignore" });
    if (result.status === 0) return candidate;
  }
  throw new Error("Python 3.9 or newer is required for the BANKING77 benchmark");
}

const windows = process.platform === "win32";
const virtualPython = resolve(
  virtualEnvironment,
  windows ? "Scripts/python.exe" : "bin/python"
);
const tsx = resolve(repositoryRoot, "node_modules/.bin", windows ? "tsx.cmd" : "tsx");

if (!existsSync(virtualPython)) {
  run(availablePython(), ["-m", "venv", virtualEnvironment]);
}
run(virtualPython, [
  "-m",
  "pip",
  "install",
  "--quiet",
  "-r",
  resolve(benchmarkRoot, "requirements.lock"),
]);
run(virtualPython, [resolve(benchmarkRoot, "run.py"), ...forwarded]);
run(tsx, [resolve(benchmarkRoot, "handoff.ts"), "--output", localResults]);
run(process.execPath, [
  resolve(repositoryRoot, "scripts/verify-banking77-benchmark.mjs"),
  "--results",
  localResults,
]);

process.stdout.write(
  "BANKING77 training, evaluation, audited handoff, and evidence verification passed.\n"
);
