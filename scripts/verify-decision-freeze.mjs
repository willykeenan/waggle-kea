#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const trialOneFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE.json");
const freezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL2.json");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

if (sha256(trialOneFreezePath) !== "8003adaf3e4613ffad2c3bfe0a075588ee89420f9a98d1a838a8ae8cfeecd668") {
  throw new Error("Trial 1 freeze was altered");
}
const failedTrialRoot = resolve(
  root,
  "benchmarks/decision-sufficiency/results/failed-trial-1-runid-boundary"
);
for (const [name, digest] of Object.entries({
  "environment.json": "10cacf56143a3737512e89839738c258150a665d4635e3ede278168fcca58714",
  "run.json": "fab3fc346d5e970c199ac8f6d3f829c27d1e2332b6801c4027c47ff2a17ee029",
  "vectors.jsonl": "0b56a66a41d5697a9bcc1257ce0774e5f130e16e9a2c06f1e3c934d6cf105859",
})) {
  if (sha256(resolve(failedTrialRoot, name)) !== digest) {
    throw new Error(`preserved Trial 1 artifact drifted: ${name}`);
  }
}

const freeze = JSON.parse(readFileSync(freezePath, "utf8"));
if (freeze.schemaVersion !== "waggle.decision-sufficiency.freeze.v1") {
  throw new Error("decision-sufficiency freeze schema drifted");
}
if (freeze.scoredOutputsObservedBeforeFreeze !== false || freeze.authorityGranted !== false) {
  throw new Error("decision-sufficiency freeze provenance or authority drifted");
}
for (const [relative, expected] of Object.entries(freeze.files)) {
  const path = resolve(root, relative);
  if (!existsSync(path)) throw new Error(`frozen file missing: ${relative}`);
  const observed = sha256(path);
  if (observed !== expected) {
    throw new Error(`frozen file drifted: ${relative} observed=${observed} expected=${expected}`);
  }
}
process.stdout.write(
  `DECISION_SUFFICIENCY_FREEZE_OK trial1=preserved trial2_files=${Object.keys(freeze.files).length}\n`
);
