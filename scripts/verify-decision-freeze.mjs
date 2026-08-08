#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const freezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE.json");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
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
process.stdout.write(`DECISION_SUFFICIENCY_FREEZE_OK ${Object.keys(freeze.files).length}\n`);
