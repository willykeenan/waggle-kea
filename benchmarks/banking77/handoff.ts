#!/usr/bin/env -S npx tsx

import { createHash } from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FileKeaLedger,
  canonicalJson,
  createWaggleV0FixtureKea,
  createWaggleV0Message,
  waggleWireBytes,
  type KeaRawMessage,
  type WaggleV0Packet,
} from "../../src/index.js";

interface TopPrediction {
  intent: string;
  probabilityPpm: number;
}

interface PredictionRow {
  caseId: string;
  sourceSplit: "test";
  sourceIndex: number;
  trueIntent: string;
  wordOnlyIntent: string;
  predictedIntent: string;
  confidencePpm: number;
  top3: TopPrediction[];
  typoEligible: boolean;
  textIncluded: false;
}

const here = dirname(fileURLToPath(import.meta.url));
const outputArgument = process.argv.indexOf("--output");
if (outputArgument >= 0 && !process.argv[outputArgument + 1]) {
  throw new Error("--output requires a result directory");
}
const resultDirectory = outputArgument >= 0
  ? resolve(process.cwd(), process.argv[outputArgument + 1])
  : resolve(here, "results/local-v1");
const predictionsPath = join(resultDirectory, "predictions.jsonl");
const runPath = join(resultDirectory, "run.json");
const handoffPath = join(resultDirectory, "handoff.json");
const modelArtifactId = "model_banking77_word_char_sgd_v1";

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function parseRows(): PredictionRow[] {
  return readFileSync(predictionsPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PredictionRow);
}

function validatePredictionRow(row: PredictionRow, labels: Set<string>): void {
  requireCondition(/^banking77_[a-f0-9]{20}$/.test(row.caseId), "caseId is invalid");
  requireCondition(row.sourceSplit === "test", "source split is invalid");
  requireCondition(Number.isSafeInteger(row.sourceIndex) && row.sourceIndex >= 0, "source index is invalid");
  requireCondition(labels.has(row.trueIntent), "true intent is outside the frozen inventory");
  requireCondition(labels.has(row.wordOnlyIntent), "word-only intent is outside the frozen inventory");
  requireCondition(labels.has(row.predictedIntent), "prediction is outside the frozen inventory");
  requireCondition(Number.isInteger(row.confidencePpm), "confidence must be integerized");
  requireCondition(row.confidencePpm >= 0 && row.confidencePpm <= 1_000_000, "confidence is outside range");
  requireCondition(row.top3.length === 3, "top3 must contain exactly three entries");
  requireCondition(new Set(row.top3.map((item) => item.intent)).size === 3, "top3 labels must be unique");
  requireCondition(row.top3.every((item) => labels.has(item.intent)), "top3 contains an unknown label");
  requireCondition(
    row.top3.every(
      (item) =>
        Number.isInteger(item.probabilityPpm) &&
        item.probabilityPpm >= 0 &&
        item.probabilityPpm <= 1_000_000
    ),
    "top3 probability is outside range"
  );
  requireCondition(
    row.top3.every(
      (item, index) => index === 0 || row.top3[index - 1].probabilityPpm >= item.probabilityPpm
    ),
    "top3 is not confidence-sorted"
  );
  requireCondition(row.top3[0].intent === row.predictedIntent, "top1 and prediction disagree");
  requireCondition(row.top3[0].probabilityPpm === row.confidencePpm, "top1 and confidence disagree");
  requireCondition(row.textIncluded === false, "prediction artifact must not redistribute source text");
}

function wireIntent(intent: string): string {
  return intent.replace(/[^a-zA-Z0-9._:/@-]/g, "_");
}

function packetFor(row: PredictionRow, predictedIntent = row.predictedIntent): WaggleV0Packet {
  const top3 = row.top3.map((item, index) =>
    index === 0
      ? { ...item, intent: wireIntent(predictedIntent) }
      : { ...item, intent: wireIntent(item.intent) }
  );
  const predictedIntentToken = wireIntent(predictedIntent);
  return {
    protocol: "waggle.v0",
    messageClass: "artifact-handoff",
    intent: "handoff",
    operation: "client.intent.route",
    references: {
      context: [row.caseId],
      artifacts: [modelArtifactId],
      evidence: [`banking77_test_${row.sourceIndex}`],
    },
    delta: {
      caseId: row.caseId,
      predictedIntent: predictedIntentToken,
      confidencePpm: row.confidencePpm,
      top3,
      route: predictedIntentToken,
      modelId: modelArtifactId,
    },
  };
}

function messageFor(row: PredictionRow, index: number, predictedIntent = row.predictedIntent) {
  return createWaggleV0Message({
    missionId: "mission_banking77_client_intent",
    workNodeId: `work_${row.caseId}`,
    senderAgentId: "agent_intent_classifier",
    receiverActorIds: ["human_client_experience_reviewer"],
    packet: packetFor(row, predictedIntent),
    contextPackId: row.caseId,
    artifactRefs: [modelArtifactId],
    evidenceRefs: [`banking77_test_${row.sourceIndex}`],
    authorityEffect: "none",
    sensitivity: "public",
    createdAt: new Date(Date.UTC(2026, 7, 5) + index * 1_000).toISOString(),
  });
}

function consumerRoute(delta: unknown, vocabulary: Map<string, string>): string {
  if (!delta || typeof delta !== "object" || Array.isArray(delta)) return "abstain";
  const route = (delta as Record<string, unknown>).route;
  return typeof route === "string" ? vocabulary.get(route) ?? "abstain" : "abstain";
}

function expectThrow(operation: () => unknown): boolean {
  try {
    operation();
    return false;
  } catch {
    return true;
  }
}

function percentile(values: number[], fraction: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.floor(fraction * sorted.length))];
}

function writeChecksums(): void {
  const names = ["environment.json", "handoff.json", "per-intent.json", "predictions.jsonl", "run.json"];
  const lines = names.map((name) => `${sha256(readFileSync(join(resultDirectory, name)))}  ${name}`);
  writeFileSync(join(resultDirectory, "SHA256SUMS"), `${lines.join("\n")}\n`, "utf8");
}

const run = JSON.parse(readFileSync(runPath, "utf8")) as {
  dataAudit: { primaryUniqueTrainDisjointTestRows: number };
  source: { files: { "test.csv": { sha256: string } } };
};
const labels = new Set(
  (JSON.parse(readFileSync(join(resultDirectory, "per-intent.json"), "utf8")) as {
    intents: Array<{ intent: string }>;
  }).intents.map((item) => item.intent)
);
const wireVocabulary = new Map([...labels].map((label) => [wireIntent(label), label]));
requireCondition(wireVocabulary.size === labels.size, "wire-safe intent vocabulary contains a collision");
const rows = parseRows();
requireCondition(rows.length === run.dataAudit.primaryUniqueTrainDisjointTestRows, "prediction denominator drifted");
requireCondition(new Set(rows.map((row) => row.caseId)).size === rows.length, "case IDs are not unique");

let exactDirectJsonAgreement = 0;
let exactDirectWaggleAgreement = 0;
let cleanFalseRejections = 0;
let authorityGrants = 0;
let ledgerEvents = 0;
let noStateAbstentions = 0;
const jsonBytes: number[] = [];
const waggleBytes: number[] = [];

for (let index = 0; index < rows.length; index++) {
  const row = rows[index];
  validatePredictionRow(row, labels);
  const directRoute = row.predictedIntent;
  const jsonRoute = (JSON.parse(canonicalJson(row)) as PredictionRow).predictedIntent;
  if (jsonRoute === directRoute) exactDirectJsonAgreement++;
  jsonBytes.push(Buffer.byteLength(canonicalJson(row), "utf8"));

  const packet = packetFor(row);
  waggleBytes.push(waggleWireBytes(packet));
  const { service, ledger } = createWaggleV0FixtureKea({
    clock: () => new Date(Date.UTC(2026, 7, 5, 1) + index * 1_000).toISOString(),
  });
  const result = service.ingest(messageFor(row, index));
  const waggleRoute = consumerRoute(result.interpretation.proposedMissionDelta, wireVocabulary);
  if (result.interpretation.disposition === "rejected") cleanFalseRejections++;
  if (waggleRoute === directRoute) exactDirectWaggleAgreement++;
  if (result.interpretation.authorityGranted !== false) authorityGrants++;
  ledgerEvents += ledger.read().length;
  if (consumerRoute(null, wireVocabulary) === "abstain") noStateAbstentions++;
}

const faultRows = [...rows]
  .sort((left, right) => sha256(left.caseId).localeCompare(sha256(right.caseId)))
  .slice(0, 64);
const faults = {
  selectedCases: faultRows.length,
  selection: "64 smallest SHA-256(caseId) values",
  exactDuplicateIdempotent: 0,
  staleHashRejected: 0,
  byteCountRejected: 0,
  immutableEnvelopeCollisionRejected: 0,
  manifestMismatchRejected: 0,
  unknownCodecRejected: 0,
  benchmarkSchemaRejected: 0,
  detectableFaultFalseAccepts: 0,
};

for (let index = 0; index < faultRows.length; index++) {
  const row = faultRows[index];
  const message = messageFor(row, index);
  const { service, ledger } = createWaggleV0FixtureKea();
  service.ingest(message);
  const beforeDuplicate = ledger.read().length;
  const duplicate = service.ingest(message);
  if (duplicate.duplicate && ledger.read().length === beforeDuplicate) faults.exactDuplicateIdempotent++;

  const staleHash = structuredClone(message);
  (staleHash.payload as WaggleV0Packet).delta = {
    ...((staleHash.payload as WaggleV0Packet).delta as Record<string, unknown>),
    route: "wrong_route",
  };
  if (expectThrow(() => service.ingest(staleHash))) faults.staleHashRejected++;

  const byteCount = structuredClone(message);
  byteCount.payloadBytes += 1;
  if (expectThrow(() => service.ingest(byteCount))) faults.byteCountRejected++;

  const collision = structuredClone(message);
  collision.receiverActorIds = ["different_receiver"];
  if (expectThrow(() => service.ingest(collision))) faults.immutableEnvelopeCollisionRejected++;

  const mismatchService = createWaggleV0FixtureKea().service;
  const manifestMismatch = structuredClone(message);
  (manifestMismatch as KeaRawMessage).codec.transport = "different_transport";
  const mismatch = mismatchService.ingest(manifestMismatch);
  if (mismatch.interpretation.disposition === "rejected" && !mismatch.interpretation.authorityGranted) {
    faults.manifestMismatchRejected++;
  }

  const unknownService = createWaggleV0FixtureKea().service;
  const unknownCodec = structuredClone(message);
  (unknownCodec as KeaRawMessage).codec.codecId = "unknown.codec";
  const unknown = unknownService.ingest(unknownCodec);
  if (unknown.interpretation.disposition === "rejected" && !unknown.interpretation.authorityGranted) {
    faults.unknownCodecRejected++;
  }

  const invalidRow = structuredClone(row);
  invalidRow.confidencePpm = 1_000_001;
  if (expectThrow(() => validatePredictionRow(invalidRow, labels))) faults.benchmarkSchemaRejected++;
}

const expectedPerFault = faultRows.length;
const detectableCounts = [
  faults.staleHashRejected,
  faults.byteCountRejected,
  faults.immutableEnvelopeCollisionRejected,
  faults.manifestMismatchRejected,
  faults.unknownCodecRejected,
  faults.benchmarkSchemaRejected,
];
faults.detectableFaultFalseAccepts = detectableCounts.reduce(
  (total, count) => total + (expectedPerFault - count),
  0
);

const ledgerRoot = mkdtempSync(join(tmpdir(), "banking77-kea-ledger-"));
let ledgerTamperRejected = false;
try {
  const fileLedger = new FileKeaLedger(ledgerRoot);
  const firstMessage = messageFor(rows[0], 0);
  fileLedger.append("message", firstMessage.messageId, firstMessage, firstMessage.createdAt);
  const original = readFileSync(fileLedger.path, "utf8");
  writeFileSync(fileLedger.path, original.replace("mission_banking77_client_intent", "mission_banking77_client_intenz"));
  ledgerTamperRejected = expectThrow(() => fileLedger.read());
} finally {
  rmSync(ledgerRoot, { recursive: true, force: true });
}

const forgedRow = rows[0];
const alternateIntent = [...labels].find((label) => label !== forgedRow.predictedIntent)!;
const forgedMessage = messageFor(forgedRow, 9999, alternateIntent);
const forgedResult = createWaggleV0FixtureKea().service.ingest(forgedMessage);
const rehashedForgeryDetected = forgedResult.interpretation.disposition === "rejected";

const passed =
  exactDirectJsonAgreement === rows.length &&
  exactDirectWaggleAgreement === rows.length &&
  cleanFalseRejections === 0 &&
  authorityGrants === 0 &&
  noStateAbstentions === rows.length &&
  faults.exactDuplicateIdempotent === faultRows.length &&
  faults.detectableFaultFalseAccepts === 0 &&
  ledgerTamperRejected &&
  rehashedForgeryDetected === false;

const handoff = {
  schemaVersion: "waggle.banking77.handoff.v1",
  status: passed ? "passed" : "failed",
  cases: rows.length,
  modelArtifactId,
  sourceTestSha256: run.source.files["test.csv"].sha256,
  informationParity: {
    directRecordFields: ["caseId", "predictedIntent", "confidencePpm", "top3"],
    exactDirectJsonAgreement,
    exactDirectWaggleAgreement,
    disagreementCount: rows.length - exactDirectWaggleAgreement,
  },
  clean: {
    falseRejections: cleanFalseRejections,
    authorityGrants,
    authorityEffectsExecuted: 0,
    ledgerEvents,
  },
  noStateControl: {
    cases: rows.length,
    abstentions: noStateAbstentions,
  },
  payloadBytes: {
    unit: "canonical UTF-8 bytes; not tokens, cost, memory, or total resources",
    canonicalJson: {
      median: percentile(jsonBytes, 0.5),
      p95: percentile(jsonBytes, 0.95),
      total: jsonBytes.reduce((sum, value) => sum + value, 0),
    },
    wagglePacket: {
      median: percentile(waggleBytes, 0.5),
      p95: percentile(waggleBytes, 0.95),
      total: waggleBytes.reduce((sum, value) => sum + value, 0),
    },
  },
  faults,
  ledgerTamper: {
    cases: 1,
    rejected: ledgerTamperRejected,
  },
  rehashedForgeryControl: {
    cases: 1,
    threatModel: "permitted writer changes payload and recomputes all content identity without a separate trust root",
    expectedDetected: false,
    detected: rehashedForgeryDetected,
    claimBoundary: "content hashes detect corruption, not permitted-writer intent",
  },
  effects: {
    providerApiCalls: 0,
    modelApiCalls: 0,
    networkCalls: 0,
    authorityEffectsExecuted: 0,
  },
  nonClaims: [
    "Exact handoff agreement does not establish better classification.",
    "The finite fault suite is not adversarial security validation.",
    "Kea qualification never grants execution authority.",
    "Payload bytes are not tokens, cost, memory, energy, or total resources.",
  ],
};

writeFileSync(handoffPath, `${JSON.stringify(handoff, null, 2)}\n`, "utf8");
writeChecksums();
console.log(
  JSON.stringify({
    ok: passed,
    cases: rows.length,
    faultCases: faultRows.length,
    exactRoutingAgreement: exactDirectWaggleAgreement,
    detectableFaultFalseAccepts: faults.detectableFaultFalseAccepts,
    authorityGrants,
    handoff: relative(process.cwd(), handoffPath),
  })
);
if (!passed) process.exitCode = 1;
