#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const trialOneFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE.json");
const trialTwoFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL2.json");
const trialThreeFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL3.json");
const trialFourFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL4.json");
const trialFiveFreezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL5.json");
const freezePath = resolve(root, "benchmarks/decision-sufficiency/FREEZE-TRIAL6.json");

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

if (sha256(trialThreeFreezePath) !== "f18d1538738d40058d2e615980b2a775ac062439f61887d6d18c7e1744477f23") {
  throw new Error("Trial 3 freeze was altered");
}
const failedTrialThreeRecord = resolve(
  root,
  "benchmarks/decision-sufficiency/results/failed-trial-3-verifier-fixture-lineage/TRIAL.json"
);
if (sha256(failedTrialThreeRecord) !== "9bfb7907a6da6654d459e6797895b40156e66afc9e20457c5447bd9958ad1775") {
  throw new Error("preserved Trial 3 record drifted");
}

if (sha256(trialFourFreezePath) !== "12a62ebf68f28f282e57c3834493609deeb24a5e3087d21bade2e08510e0d53e") {
  throw new Error("Trial 4 freeze was altered");
}
const failedTrialFourRecord = resolve(
  root,
  "benchmarks/decision-sufficiency/results/failed-trial-4-verifier-sample-shape/TRIAL.json"
);
if (sha256(failedTrialFourRecord) !== "81241ec237f357da803a005795dc24c06932994369b915e24c6c45ed6897d400") {
  throw new Error("preserved Trial 4 record drifted");
}

if (sha256(trialFiveFreezePath) !== "270dafa5f9d8124d6f80cb37a8883bf35e078945dc850a19583d1280c53a80aa") {
  throw new Error("Trial 5 freeze was altered");
}
const failedTrialFiveRoot = resolve(
  root,
  "benchmarks/decision-sufficiency/results/failed-trial-5-consumer-shape"
);
for (const [name, digest] of Object.entries({
  "SHA256SUMS": "52858e2e39d0127ab3563f990fcc17445c6bf3bc57c7d28a7e7fc02495c44782",
  "TRIAL.json": "e2f9f88834dbe95ea5cf67e4c8307683c09a0381c75562d3cd069842687e674d",
  "attacks.json": "6fc6c640e3ef5ad352e0312685f9f886d4d133ffdfb973f1aa8bb056b5e858c7",
  "decisions.jsonl.gz": "6bb996fad76e807c5047a9af28f45387aa8727dadf58483f08441ca924575cea",
  "environment.json": "2d575f4866268fdc7a7527539500d36401a414e902a0d8c7888f434495d3fec8",
  "evaluation.json": "e1746c116cddac34cbe17662d86242515f8f0f4ac7b792382814ba7c7e4d528f",
  "policies.json": "fcb871a1affa1cf38486b019f3f5d57047d9f117dc89b821150cba2ad652020e",
  "run.json": "29eb273e052be7e0d8a8dc5e606af4fa73ef28a180d8bd7efdde2bfda64e5f1d",
  "samples.jsonl": "e8ed216b8f65ba09cca70a3b88326461144dbe21f535bab259cd983e3b9b9f19",
  "vectors.jsonl": "0b56a66a41d5697a9bcc1257ce0774e5f130e16e9a2c06f1e3c934d6cf105859",
})) {
  if (sha256(resolve(failedTrialFiveRoot, name)) !== digest) {
    throw new Error(`preserved Trial 5 artifact drifted: ${name}`);
  }
}

if (sha256(trialTwoFreezePath) !== "4ea323ac5b9611c672ee639f4c7347a1520eae3da16d068bd8079ff269de928c") {
  throw new Error("Trial 2 freeze was altered");
}
const failedTrialTwoRoot = resolve(
  root,
  "benchmarks/decision-sufficiency/results/failed-trial-2-verifier-label-lineage"
);
for (const [name, digest] of Object.entries({
  "SHA256SUMS": "32f149c28b5a6013ca6e95d753841da731c9318eca3e6d459b88ca86ce9325aa",
  "TRIAL.json": "0d7610c67d39a95155b28906aafb0baf05a01645d002888a849a2331c6209104",
  "attacks.json": "6fc6c640e3ef5ad352e0312685f9f886d4d133ffdfb973f1aa8bb056b5e858c7",
  "decisions.jsonl.gz": "6bb996fad76e807c5047a9af28f45387aa8727dadf58483f08441ca924575cea",
  "environment.json": "538c96017b484f3ecb5f3b3a3b02edb6b1e17bc925035da9817bca5ce3a6b72b",
  "evaluation.json": "e1746c116cddac34cbe17662d86242515f8f0f4ac7b792382814ba7c7e4d528f",
  "policies.json": "fcb871a1affa1cf38486b019f3f5d57047d9f117dc89b821150cba2ad652020e",
  "run.json": "29eb273e052be7e0d8a8dc5e606af4fa73ef28a180d8bd7efdde2bfda64e5f1d",
  "samples.jsonl": "e8ed216b8f65ba09cca70a3b88326461144dbe21f535bab259cd983e3b9b9f19",
  "vectors.jsonl": "0b56a66a41d5697a9bcc1257ce0774e5f130e16e9a2c06f1e3c934d6cf105859",
})) {
  if (sha256(resolve(failedTrialTwoRoot, name)) !== digest) {
    throw new Error(`preserved Trial 2 artifact drifted: ${name}`);
  }
}

const freeze = JSON.parse(readFileSync(freezePath, "utf8"));
if (freeze.schemaVersion !== "waggle.decision-sufficiency.freeze.v1") {
  throw new Error("decision-sufficiency freeze schema drifted");
}
if (
  freeze.scoredOutputsObservedBeforeFreeze !== true ||
  freeze.scientificContractChangedAfterOutput !== false ||
  freeze.authorityGranted !== false
) {
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
  `DECISION_SUFFICIENCY_FREEZE_OK trial1=preserved trial2=preserved trial3=preserved trial4=preserved trial5=preserved trial6_files=${Object.keys(freeze.files).length}\n`
);
