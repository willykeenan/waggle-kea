#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const resultArgument = process.argv.indexOf("--results");
if (resultArgument >= 0 && !process.argv[resultArgument + 1]) {
  throw new Error("--results requires a result directory");
}
const results = resultArgument >= 0
  ? resolve(repoRoot, process.argv[resultArgument + 1])
  : resolve(repoRoot, "benchmarks/banking77/results/reference-v1");
const required = [
  "environment.json",
  "handoff.json",
  "per-intent.json",
  "predictions.jsonl",
  "run.json",
];

function fail(message) {
  throw new Error(`BANKING77 benchmark verification failed: ${message}`);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function parseJson(name) {
  return JSON.parse(readFileSync(resolve(results, name), "utf8"));
}

for (const name of required) {
  requireCondition(existsSync(resolve(results, name)), `missing ${name}`);
}
const checksumPath = resolve(results, "SHA256SUMS");
requireCondition(existsSync(checksumPath), "missing SHA256SUMS");
const checksumEntries = readFileSync(checksumPath, "utf8")
  .trim()
  .split("\n")
  .map((line) => {
    const match = /^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$/.exec(line);
    requireCondition(match, `malformed checksum line: ${line}`);
    return { digest: match[1], name: match[2] };
  });
requireCondition(checksumEntries.length === required.length, "checksum denominator drifted");
requireCondition(
  checksumEntries.map((entry) => entry.name).join("\n") === [...required].sort().join("\n"),
  "checksums do not cover exactly the required artifacts"
);
for (const entry of checksumEntries) {
  requireCondition(sha256(resolve(results, entry.name)) === entry.digest, `${entry.name} digest mismatch`);
}

const run = parseJson("run.json");
const handoff = parseJson("handoff.json");
const perIntent = parseJson("per-intent.json");
const environment = parseJson("environment.json");
const predictionLines = readFileSync(resolve(results, "predictions.jsonl"), "utf8")
  .split("\n")
  .filter(Boolean);
const predictions = predictionLines.map((line) => JSON.parse(line));

requireCondition(run.schemaVersion === "waggle.banking77.benchmark.v1", "run schema mismatch");
requireCondition(run.status === "exploratory-valid", "run is not exploratory-valid");
requireCondition(run.preRegistered === false && run.testInformedDesign === true, "exploratory status is obscured");
requireCondition(
  run.source.upstreamCommit === "57ec275d8078af65b7731c2a98be812d844a6d6b",
  "source commit drifted"
);
const expectedHashes = {
  "categories.json": "53261da888122daf2d120d925458631d9619e15d82e56052e7a42e535ce32b63",
  "train.csv": "b06e26ac675513959a63135f11b94ea7786ed02da65db93a5650d8838cbc664b",
  "test.csv": "d12d6e3bc4c3103966ae786dc435913c0c563dfa328f5a3646d0e62cfeeb474d",
};
for (const [name, digest] of Object.entries(expectedHashes)) {
  requireCondition(run.source.files[name].sha256 === digest, `${name} source hash drifted`);
}
const expectedAudit = {
  rawTrainRows: 10003,
  rawTestRows: 3080,
  categories: 77,
  normalizedTrainGroups: 9972,
  normalizedTestGroups: 3076,
  ambiguousTrainGroups: 1,
  ambiguousTestGroups: 1,
  normalizedTrainTestOverlapGroups: 25,
  cleanUniqueTrainRows: 9971,
  primaryUniqueTrainDisjointTestRows: 3050,
  postFilterOverlapGroups: 0,
};
for (const [key, value] of Object.entries(expectedAudit)) {
  requireCondition(run.dataAudit[key] === value, `data-audit count drifted for ${key}`);
}
requireCondition(
  Object.keys(run.dataAudit).length === Object.keys(expectedAudit).length,
  "data-audit contains unexpected fields"
);

const canonical = run.classification.canonical;
const observedDelta = canonical.wordPlusCharacter.macroF1 - canonical.wordOnly.macroF1;
requireCondition(Math.abs(observedDelta - canonical.pairedMacroF1Delta) < 1e-12, "paired macro-F1 delta mismatch");
const interval = run.classification.pairedBootstrap.pairedDeltaMacroF1Interval95;
requireCondition(run.classification.pairedBootstrap.draws === 2000, "bootstrap draw count drifted");
requireCondition(interval.length === 2 && interval.every(Number.isFinite), "bootstrap interval is incomplete");
const expectedVerdict = observedDelta > 0 && interval[0] > 0
  ? "H1_SUPPORTED_EXPLORATORY"
  : "H0_RETAINED";
requireCondition(run.scientificVerdict === expectedVerdict, "scientific verdict does not match interval");
requireCondition(run.classification.seedSensitivity.length === 5, "seed-sensitivity denominator drifted");
requireCondition(run.classification.shuffledLabelControl.passed === true, "shuffled-label control failed");
requireCondition(run.classification.shuffledLabelControl.accuracy <= 0.05, "shuffled-label accuracy tripwire failed");
requireCondition(run.classification.shuffledLabelControl.macroF1 <= 0.05, "shuffled-label macro-F1 tripwire failed");
for (const model of [canonical.wordOnly, canonical.wordPlusCharacter]) {
  for (const metric of ["accuracy", "macroF1", "logLoss", "multiclassBrier", "expectedCalibrationError", "top3Accuracy"]) {
    requireCondition(Number.isFinite(model[metric]), `missing canonical ${metric}`);
  }
  requireCondition(model.riskCoverage.length === 21, "risk-coverage curve is incomplete");
}
requireCondition(run.seededTypoStress.changedCases > 0, "typo stress changed zero cases");
requireCondition(run.predictionArtifact.rows === 3050, "prediction artifact denominator drifted");
requireCondition(run.predictionArtifact.textIncluded === false, "source text was redistributed");
requireCondition(run.effects.providerApiCalls === 0 && run.effects.modelApiCalls === 0, "provider/model API call recorded");
requireCondition(run.effects.authorityEffectsExecuted === 0, "authority effect recorded");
requireCondition(Array.isArray(run.nonClaims) && run.nonClaims.length >= 9, "non-claims are incomplete");

requireCondition(predictions.length === 3050, "prediction row count drifted");
requireCondition(new Set(predictions.map((row) => row.caseId)).size === 3050, "prediction case IDs are not unique");
requireCondition(predictions.every((row) => row.textIncluded === false && !("text" in row)), "prediction artifact contains source text");
requireCondition(perIntent.intents.length === 77, "per-intent denominator drifted");

requireCondition(handoff.schemaVersion === "waggle.banking77.handoff.v1", "handoff schema mismatch");
requireCondition(handoff.status === "passed", "handoff did not pass");
requireCondition(handoff.cases === 3050, "handoff denominator drifted");
requireCondition(handoff.informationParity.exactDirectJsonAgreement === 3050, "JSON routing mismatch");
requireCondition(handoff.informationParity.exactDirectWaggleAgreement === 3050, "Waggle routing mismatch");
requireCondition(handoff.informationParity.disagreementCount === 0, "handoff disagreement recorded");
requireCondition(handoff.clean.falseRejections === 0, "clean handoff rejection recorded");
requireCondition(handoff.clean.authorityGrants === 0, "authority grant recorded");
requireCondition(handoff.clean.authorityEffectsExecuted === 0, "authority effect recorded");
requireCondition(handoff.noStateControl.abstentions === 3050, "no-state control did not fully abstain");
requireCondition(handoff.faults.selectedCases === 64, "fault sample denominator drifted");
requireCondition(handoff.faults.exactDuplicateIdempotent === 64, "duplicate idempotency failed");
requireCondition(handoff.faults.detectableFaultFalseAccepts === 0, "detectable fault was accepted");
requireCondition(handoff.ledgerTamper.rejected === true, "ledger tamper was not rejected");
requireCondition(handoff.rehashedForgeryControl.expectedDetected === false, "forgery expectation is overstated");
requireCondition(handoff.rehashedForgeryControl.detected === false, "forgery result contradicts threat model");
requireCondition(
  handoff.effects.providerApiCalls === 0 &&
    handoff.effects.modelApiCalls === 0 &&
    handoff.effects.networkCalls === 0 &&
    handoff.effects.authorityEffectsExecuted === 0,
  "handoff external/provider/authority effect recorded"
);
requireCondition(environment.scoredPhaseNetworkCalls === 0, "scored-phase network call recorded");
requireCondition(environment.providerApiCalls === 0, "environment records provider calls");

const summary = {
  ok: true,
  runId: run.runId,
  scientificVerdict: run.scientificVerdict,
  primaryTestCases: run.dataAudit.primaryUniqueTrainDisjointTestRows,
  wordOnlyMacroF1: canonical.wordOnly.macroF1,
  wordPlusCharacterMacroF1: canonical.wordPlusCharacter.macroF1,
  pairedMacroF1Delta: observedDelta,
  pairedDeltaInterval95: interval,
  exactWaggleRoutingAgreement: handoff.informationParity.exactDirectWaggleAgreement,
  detectableFaultFalseAccepts: handoff.faults.detectableFaultFalseAccepts,
  authorityGrants: handoff.clean.authorityGrants,
};
console.log(JSON.stringify(summary));
