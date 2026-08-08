#!/usr/bin/env -S npx tsx
/**
 * Frozen decision-sufficiency experiment coordinator (Waggle + Kea v0.3).
 *
 * Full mode reads text-free prediction-state artifacts from the runner, derives
 * the 12 SHA-256 four-action policies, evaluates every matched control arm,
 * measures byte boundaries, runs attack probes, applies primary admission
 * gates, and writes the frozen evaluation inventory. The synthetic --self-test
 * path never loads BANKING77 outputs and never inspects scored results.
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import {
  MemoryKeaLedger,
  canonicalJson,
  contentId,
  createDecisionCertificate,
  createDecisionPolicy,
  createWaggleV0Message,
  decisionStateBytes,
  decisionVectorId,
  qualifyDecisionCertificate,
  consumeQualifiedDecision,
  referenceDecision,
  verifyDecisionCertificateMath,
  waggleWireBytes,
  type KeaDecisionQualification,
  type WaggleDecisionCertificate,
  type WaggleDecisionPolicy,
  type WaggleV0Packet,
} from "../../src/index.js";

// ---------------------------------------------------------------------------
// Paths, schemas, config
// ---------------------------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONFIG = join(HERE, "config.v1.json");
const DEFAULT_OUTPUT = join(HERE, "results/local-v1");

const EVALUATION_SCHEMA = "waggle.decision-sufficiency.evaluation.v1";
const ENVIRONMENT_SCHEMA = "waggle.decision-sufficiency.environment.v1";
const POLICIES_SCHEMA = "waggle.decision-sufficiency.policies.v1";
const ATTACKS_SCHEMA = "waggle.decision-sufficiency.attacks.v1";
const VECTOR_SCHEMA = "waggle.decision-sufficiency.vector.v1";
const DECISION_ROW_SCHEMA = "waggle.decision-sufficiency.decision.v1";
const SAMPLE_SCHEMA = "waggle.decision-sufficiency.sample.v1";
const FULL_VECTOR_STATE_SCHEMA = "waggle.decision-sufficiency.full-vector.v1";
const COST_SUMMARY_SCHEMA = "waggle.decision-sufficiency.cost-summary.v1";

const REQUIRED_ARTIFACTS = [
  "attacks.json",
  "decisions.jsonl.gz",
  "environment.json",
  "evaluation.json",
  "policies.json",
  "run.json",
  "samples.jsonl",
  "vectors.jsonl",
] as const;

interface DecisionSufficiencyConfig {
  schemaVersion: "waggle.decision-sufficiency.config.v1";
  status: string;
  dataset: string;
  sourceContract: string;
  classifierContract: string;
  canonicalSeed: number;
  probabilityScale: number;
  policyFamily: {
    type: "sha256-partitioned-four-action-zero-one-cost";
    actionCount: number;
    matchCostUnits: number;
    mismatchCostUnits: number;
    seeds: number[];
  };
  maxRevealedProbabilities: number;
  fixedSafeControls: number[];
  bootstrap: {
    method: "case-clustered-percentile";
    seed: number;
    draws: number;
  };
  primaryAdmission: {
    adaptiveSafeCoverageMinimum: number;
    adaptiveCoverageGainOverSafeK1Minimum: number;
    adaptiveDecisionMismatchesMaximum: number;
    fullVectorDecisionMismatchesMaximum: number;
    expectedCostSummaryDecisionMismatchesMaximum: number;
    naiveTop1DecisionMismatchesMinimum: number;
    noStateContinuesMaximum: number;
  };
  continuityReference: {
    accuracy: number;
    macroF1: number;
    maximumAbsoluteDrift: number;
  };
  certificateSampleCases: number;
  effects: {
    providerApiCallsMaximum: number;
    modelApiCallsMaximum: number;
    authorityEffectsMaximum: number;
  };
}

interface PredictionVectorRow {
  schemaVersion?: string;
  caseId: string;
  sourceIndex?: number;
  vectorId: string;
  probabilityScale?: number;
  probabilities: number[];
  trueIntent?: string;
  textIncluded?: boolean;
  labelIds?: string[];
  [key: string]: unknown;
}

interface CasePolicyDecision {
  schemaVersion: typeof DECISION_ROW_SCHEMA;
  caseId: string;
  policyId: string;
  policySeed: number;
  vectorId: string;
  authorityGranted: false;
  fullVector: {
    disposition: "continue" | "insufficient_confidence";
    actionId: string | null;
  };
  fullVectorReconstruction: {
    encoding: "canonical-json";
    vectorId: string;
    disposition: "continue" | "insufficient_confidence";
    actionId: string | null;
  };
  expectedCostSummary: {
    schemaVersion: typeof COST_SUMMARY_SCHEMA;
    summaryId: string;
    caseId: string;
    policyId: string;
    vectorId: string;
    actionCostUnits: number[];
    disposition: "continue" | "insufficient_confidence";
    actionId: string | null;
    authorityGranted: false;
  };
  adaptive: { certificate: WaggleDecisionCertificate };
  safeK1: { certificate: WaggleDecisionCertificate };
  safeK3: { certificate: WaggleDecisionCertificate };
  naiveTop1: {
    disposition: "continue" | "insufficient_confidence";
    actionId: string | null;
  };
  noState: {
    disposition: "abstain";
    actionId: null;
  };
  qualification: KeaDecisionQualification;
  restricted: {
    disposition: "continue" | "insufficient_confidence" | "abstain";
    actionId: string | null;
    authorityGranted: false;
  };
  bytes: {
    fullVector: number;
    certificate: number;
    qualification: number;
    wagglePacket: number;
    waggleMessageEnvelope: number;
    ledger: number;
    expectedCostSummary: number;
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function writeCanonicalJson(path: string, value: unknown): void {
  writeFileSync(path, `${canonicalJson(value)}\n`, "utf8");
}

function writeJsonl(path: string, rows: readonly unknown[]): void {
  writeFileSync(path, `${rows.map((row) => canonicalJson(row)).join("\n")}\n`, "utf8");
}

function wireLabel(label: string): string {
  return label.replace(/[^a-zA-Z0-9._:/@-]/g, "_");
}

function parseArgs(argv: string[]) {
  const flags = new Set(argv);
  const get = (name: string): string | undefined => {
    const index = argv.indexOf(name);
    return index >= 0 ? argv[index + 1] : undefined;
  };
  return {
    selfTest: flags.has("--self-test"),
    input: get("--input"),
    output: get("--output") ?? DEFAULT_OUTPUT,
    config: get("--config") ?? DEFAULT_CONFIG,
  };
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function percentile(values: number[], fraction: number): number {
  if (values.length === 0) return Number.NaN;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.floor(fraction * sorted.length)));
  return sorted[index];
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function summarizeIntegers(values: readonly number[]) {
  requireCondition(values.length > 0, "cannot summarize an empty integer series");
  return {
    minimum: Math.min(...values),
    median: median([...values]),
    p95: percentile([...values], 0.95),
    maximum: Math.max(...values),
    total: values.reduce((sum, value) => sum + value, 0),
  };
}

function classifierContinuity(
  rows: readonly PredictionVectorRow[],
  labelIds: readonly string[],
  reference: DecisionSufficiencyConfig["continuityReference"]
) {
  const labels = [...labelIds];
  const byLabel = new Map(labels.map((label) => [label, { tp: 0, fp: 0, fn: 0 }]));
  let correct = 0;
  for (const row of rows) {
    requireCondition(typeof row.trueIntent === "string", `trueIntent missing for ${row.caseId}`);
    requireCondition(byLabel.has(row.trueIntent), `unknown trueIntent for ${row.caseId}`);
    let predictedIndex = 0;
    for (let index = 1; index < row.probabilities.length; index += 1) {
      if (row.probabilities[index] > row.probabilities[predictedIndex]) predictedIndex = index;
    }
    const predicted = labels[predictedIndex];
    if (predicted === row.trueIntent) {
      correct += 1;
      byLabel.get(predicted)!.tp += 1;
    } else {
      byLabel.get(predicted)!.fp += 1;
      byLabel.get(row.trueIntent)!.fn += 1;
    }
  }
  const accuracy = correct / rows.length;
  const macroF1 =
    [...byLabel.values()].reduce((sum, value) => {
      const denominator = 2 * value.tp + value.fp + value.fn;
      return sum + (denominator === 0 ? 0 : (2 * value.tp) / denominator);
    }, 0) / labels.length;
  const accuracyAbsoluteDrift = Math.abs(accuracy - reference.accuracy);
  const macroF1AbsoluteDrift = Math.abs(macroF1 - reference.macroF1);
  return {
    quantizedVectorAccuracy: accuracy,
    quantizedVectorMacroF1: macroF1,
    publishedV02Accuracy: reference.accuracy,
    publishedV02MacroF1: reference.macroF1,
    maximumAbsoluteDrift: reference.maximumAbsoluteDrift,
    accuracyAbsoluteDrift,
    macroF1AbsoluteDrift,
    continuityPassed:
      accuracyAbsoluteDrift <= reference.maximumAbsoluteDrift &&
      macroF1AbsoluteDrift <= reference.maximumAbsoluteDrift,
  };
}

function compactCertificate(certificate: WaggleDecisionCertificate) {
  return {
    certificateId: certificate.certificateId,
    disposition: certificate.disposition,
    actionId: certificate.actionId,
    revealedCount: certificate.revealed.length,
    residualUnits: certificate.residualUnits,
    authorityGranted: false as const,
  };
}

// ---------------------------------------------------------------------------
// Policy family (frozen SHA-256 partition: SHA-256(seed:labelId))
// ---------------------------------------------------------------------------

export function assignActionIndex(seed: number, labelId: string, actionCount: number): number {
  // Independent verifier regenerates via SHA-256(`${seed}:${labelId}`).
  const digest = createHash("sha256").update(`${seed}:${labelId}`, "utf8").digest();
  return digest.readUInt32BE(0) % actionCount;
}

export function derivePolicies(
  config: DecisionSufficiencyConfig,
  rawLabelIds: readonly string[]
): WaggleDecisionPolicy[] {
  const labelIds = rawLabelIds.map(wireLabel);
  requireCondition(new Set(labelIds).size === labelIds.length, "labelIds must be unique after wire sanitization");
  requireCondition(labelIds.length >= 2, "policy family requires at least two labels");

  const { actionCount, matchCostUnits, mismatchCostUnits, seeds } = config.policyFamily;
  requireCondition(actionCount === 4, "frozen policy family requires four actions");
  requireCondition(seeds.length >= 1, "policy family requires at least one seed");

  const actionIds = Array.from({ length: actionCount }, (_, index) => `action_${index}`);

  return seeds.map((seed) => {
    const assignment = labelIds.map((labelId) => assignActionIndex(seed, labelId, actionCount));
    const occupancy = Array.from({ length: actionCount }, () => 0);
    for (const actionIndex of assignment) occupancy[actionIndex] += 1;
    requireCondition(
      occupancy.every((count) => count > 0),
      `policy seed ${seed} failed the every-action occupancy invariant`
    );
    const costMatrix = actionIds.map((_, actionIndex) =>
      assignment.map((assigned) => (assigned === actionIndex ? matchCostUnits : mismatchCostUnits))
    );
    return createDecisionPolicy({ labelIds: [...labelIds], actionIds: [...actionIds], costMatrix });
  });
}

// ---------------------------------------------------------------------------
// Control arms
// ---------------------------------------------------------------------------

function naiveTop1Action(
  probabilities: readonly number[],
  policy: WaggleDecisionPolicy
): { disposition: "continue" | "insufficient_confidence"; actionId: string | null } {
  let bestIndex = 0;
  for (let index = 1; index < probabilities.length; index += 1) {
    if (
      probabilities[index] > probabilities[bestIndex] ||
      (probabilities[index] === probabilities[bestIndex] && index < bestIndex)
    ) {
      bestIndex = index;
    }
  }
  const costs = policy.costMatrix.map((row) => row[bestIndex]);
  const minCost = Math.min(...costs);
  const winners = costs
    .map((cost, actionIndex) => ({ cost, actionIndex }))
    .filter((item) => item.cost === minCost);
  if (winners.length !== 1) {
    return { disposition: "insufficient_confidence", actionId: null };
  }
  return {
    disposition: "continue",
    actionId: policy.actionIds[winners[0].actionIndex],
  };
}

function certificatePacket(certificate: WaggleDecisionCertificate): WaggleV0Packet {
  return {
    protocol: "waggle.v0",
    messageClass: "artifact-handoff",
    intent: "handoff",
    operation: "decision.certificate.handoff",
    references: {
      context: [certificate.caseId],
      artifacts: [certificate.certificateId],
      evidence: [certificate.vectorId],
    },
    delta: {
      certificateId: certificate.certificateId,
      policyId: certificate.policyId,
      vectorId: certificate.vectorId,
      disposition: certificate.disposition,
      actionId: certificate.actionId,
      revealed: certificate.revealed,
      residualUnits: certificate.residualUnits,
      pairwiseLowerAdvantages: certificate.pairwiseLowerAdvantages,
      authorityGranted: false,
    },
  };
}

function measureTransportBytes(
  certificate: WaggleDecisionCertificate,
  qualification: KeaDecisionQualification,
  caseId: string
): {
  fullVector: number;
  certificate: number;
  qualification: number;
  wagglePacket: number;
  waggleMessageEnvelope: number;
  ledger: number;
  expectedCostSummary: number;
} {
  const packet = certificatePacket(certificate);
  const message = createWaggleV0Message({
    missionId: "mission_decision_sufficiency",
    workNodeId: `work_${caseId}`,
    senderAgentId: "agent_decision_producer",
    receiverActorIds: ["agent_restricted_consumer"],
    packet,
    contextPackId: caseId,
    artifactRefs: [certificate.certificateId],
    evidenceRefs: [certificate.vectorId],
    authorityEffect: "none",
    sensitivity: "public",
    createdAt: "2026-08-05T00:00:00.000Z",
  });
  const syntheticLedger = new MemoryKeaLedger();
  syntheticLedger.append(
    "interpretation",
    message.messageId,
    {
      interpretationId: contentId("keainterp", {
        certificateId: certificate.certificateId,
        qualificationId: qualification.qualificationId,
      }),
      messageId: message.messageId,
      disposition: qualification.disposition === "qualified" ? "verified" : "rejected",
      humanGloss: "decision-certificate-qualification",
      proposedMissionDelta: packet.delta,
      verification: {
        exactRoundTrip: true,
        decoderBehavioralParity: "not-evaluated",
        policyParity: "not-evaluated",
      },
      budget: { maxUndecodableBytes: 0, usedUndecodableBytes: 0, exceeded: false },
      watchSignals: [],
      authorityGranted: false,
      createdAt: "2026-08-05T00:00:00.000Z",
    } as never,
    "2026-08-05T00:00:00.000Z"
  );

  return {
    fullVector: 0,
    certificate: decisionStateBytes(certificate),
    qualification: decisionStateBytes(qualification),
    wagglePacket: waggleWireBytes(packet),
    waggleMessageEnvelope: decisionStateBytes(message),
    ledger: decisionStateBytes(syntheticLedger.read()),
    expectedCostSummary: 0,
  };
}

function canonicalFullVectorState(input: {
  vectorId: string;
  probabilityScale: number;
  probabilities: readonly number[];
}) {
  return {
    schemaVersion: FULL_VECTOR_STATE_SCHEMA,
    vectorId: input.vectorId,
    probabilityScale: input.probabilityScale,
    probabilities: [...input.probabilities],
  };
}

function createExpectedCostSummary(input: {
  caseId: string;
  vectorId: string;
  policy: WaggleDecisionPolicy;
  disposition: "continue" | "insufficient_confidence";
  actionId: string | null;
  actionCostUnits: readonly number[];
}) {
  const body = {
    schemaVersion: COST_SUMMARY_SCHEMA,
    caseId: input.caseId,
    policyId: input.policy.policyId,
    vectorId: input.vectorId,
    actionCostUnits: [...input.actionCostUnits],
    disposition: input.disposition,
    actionId: input.actionId,
    authorityGranted: false as const,
  };
  return { ...body, summaryId: contentId("decisioncostsummary", body) };
}

function evaluateCasePolicy(input: {
  caseId: string;
  probabilities: readonly number[];
  probabilityScale: number;
  policy: WaggleDecisionPolicy;
  policySeed: number;
  maxRevealed: number;
  vectorId: string;
  measureTransport: boolean;
}): CasePolicyDecision {
  const full = referenceDecision(input.probabilities, input.probabilityScale, input.policy);
  const encodedFullVector = Buffer.from(
    canonicalJson(
      canonicalFullVectorState({
        vectorId: input.vectorId,
        probabilityScale: input.probabilityScale,
        probabilities: input.probabilities,
      })
    ),
    "utf8"
  );
  const decodedFullVector = JSON.parse(encodedFullVector.toString("utf8")) as {
    vectorId: string;
    probabilityScale: number;
    probabilities: number[];
  };
  const reconstructedVectorId = decisionVectorId(
    decodedFullVector.probabilities,
    decodedFullVector.probabilityScale
  );
  const reconstructed = referenceDecision(
    decodedFullVector.probabilities,
    decodedFullVector.probabilityScale,
    input.policy
  );
  const expectedCostSummary = createExpectedCostSummary({
    caseId: input.caseId,
    vectorId: input.vectorId,
    policy: input.policy,
    disposition: full.disposition,
    actionId: full.actionId,
    actionCostUnits: full.actionCostUnits,
  });
  const adaptiveCertificate = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: input.maxRevealed,
  });
  const qualification = qualifyDecisionCertificate({
    certificate: adaptiveCertificate,
    policy: input.policy,
    fullProbabilityVector: input.probabilities,
  });
  const restricted = consumeQualifiedDecision({
    certificate: adaptiveCertificate,
    policy: input.policy,
    qualification,
  });

  requireCondition(adaptiveCertificate.authorityGranted === false, "certificate granted authority");
  requireCondition(qualification.authorityGranted === false, "qualification granted authority");
  requireCondition(restricted.authorityGranted === false, "consumer granted authority");

  const safeK1Certificate = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: 1,
  });
  const safeK3Certificate = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: 3,
  });
  const naive = naiveTop1Action(input.probabilities, input.policy);

  const bytes = input.measureTransport
    ? measureTransportBytes(adaptiveCertificate, qualification, input.caseId)
    : {
        fullVector: 0,
        certificate: decisionStateBytes(adaptiveCertificate),
        qualification: decisionStateBytes(qualification),
        wagglePacket: 0,
        waggleMessageEnvelope: 0,
        ledger: 0,
        expectedCostSummary: 0,
      };
  bytes.fullVector = encodedFullVector.byteLength;
  bytes.expectedCostSummary = decisionStateBytes(expectedCostSummary);

  return {
    schemaVersion: DECISION_ROW_SCHEMA,
    caseId: input.caseId,
    policyId: input.policy.policyId,
    policySeed: input.policySeed,
    vectorId: input.vectorId,
    authorityGranted: false,
    fullVector: {
      disposition: full.disposition,
      actionId: full.actionId,
    },
    fullVectorReconstruction: {
      encoding: "canonical-json",
      vectorId: reconstructedVectorId,
      disposition: reconstructed.disposition,
      actionId: reconstructed.actionId,
    },
    expectedCostSummary,
    adaptive: { certificate: adaptiveCertificate },
    safeK1: { certificate: safeK1Certificate },
    safeK3: { certificate: safeK3Certificate },
    naiveTop1: {
      disposition: naive.disposition,
      actionId: naive.actionId,
    },
    noState: {
      disposition: "abstain",
      actionId: null,
    },
    qualification,
    restricted: {
      disposition: restricted.disposition,
      actionId: restricted.actionId,
      authorityGranted: false,
    },
    bytes,
  };
}

// ---------------------------------------------------------------------------
// Metrics, bootstrap, primary gates
// ---------------------------------------------------------------------------

function aggregateMetrics(records: readonly CasePolicyDecision[]): {
  fullVectorNonTiedDenominator: number;
  adaptiveSafeContinues: number;
  safeK1Continues: number;
  safeK3Continues: number;
  adaptiveSafeCoverage: number;
  safeK1Coverage: number;
  safeK3Coverage: number;
  adaptiveCoverageGainOverSafeK1: number;
  adaptiveDecisionMismatches: number;
  fullVectorDecisionMismatches: number;
  expectedCostSummaryDecisionMismatches: number;
  naiveTop1DecisionMismatches: number;
  noStateContinues: number;
} {
  let fullVectorNonTied = 0;
  let adaptiveSafeContinues = 0;
  let safeK1Continues = 0;
  let safeK3Continues = 0;
  let adaptiveDecisionMismatches = 0;
  let fullVectorDecisionMismatches = 0;
  let expectedCostSummaryDecisionMismatches = 0;
  let naiveTop1DecisionMismatches = 0;
  let noStateContinues = 0;

  for (const row of records) {
    if (
      row.fullVectorReconstruction.vectorId !== row.vectorId ||
      row.fullVectorReconstruction.disposition !== row.fullVector.disposition ||
      row.fullVectorReconstruction.actionId !== row.fullVector.actionId
    ) {
      fullVectorDecisionMismatches += 1;
    }
    if (
      row.expectedCostSummary.disposition !== row.fullVector.disposition ||
      row.expectedCostSummary.actionId !== row.fullVector.actionId
    ) {
      expectedCostSummaryDecisionMismatches += 1;
    }

    // Safe coverage denominator is full-vector non-tied case-policy decisions only.
    if (row.fullVector.disposition === "continue") {
      fullVectorNonTied += 1;
      if (row.adaptive.certificate.disposition === "continue") {
        adaptiveSafeContinues += 1;
        if (row.adaptive.certificate.actionId !== row.fullVector.actionId) {
          adaptiveDecisionMismatches += 1;
        }
      }
      if (row.safeK1.certificate.disposition === "continue") safeK1Continues += 1;
      if (row.safeK3.certificate.disposition === "continue") safeK3Continues += 1;
      if (
        row.naiveTop1.disposition !== "continue" ||
        row.naiveTop1.actionId !== row.fullVector.actionId
      ) {
        naiveTop1DecisionMismatches += 1;
      }
    } else if (row.adaptive.certificate.disposition === "continue") {
      // Adaptive must not continue when the full vector is unresolved.
      adaptiveDecisionMismatches += 1;
    }

    if (row.noState.disposition === "continue") noStateContinues += 1;
  }

  const adaptiveSafeCoverage =
    fullVectorNonTied === 0 ? 0 : adaptiveSafeContinues / fullVectorNonTied;
  const safeK1Coverage = fullVectorNonTied === 0 ? 0 : safeK1Continues / fullVectorNonTied;
  const safeK3Coverage = fullVectorNonTied === 0 ? 0 : safeK3Continues / fullVectorNonTied;

  return {
    fullVectorNonTiedDenominator: fullVectorNonTied,
    adaptiveSafeContinues,
    safeK1Continues,
    safeK3Continues,
    adaptiveSafeCoverage,
    safeK1Coverage,
    safeK3Coverage,
    adaptiveCoverageGainOverSafeK1: adaptiveSafeCoverage - safeK1Coverage,
    adaptiveDecisionMismatches,
    fullVectorDecisionMismatches,
    expectedCostSummaryDecisionMismatches,
    naiveTop1DecisionMismatches,
    noStateContinues,
  };
}

function caseClusteredBootstrap(
  records: readonly CasePolicyDecision[],
  seed: number,
  draws: number
): {
  method: "case-clustered-percentile";
  seed: number;
  draws: number;
  adaptiveSafeCoverageInterval95: [number, number];
  adaptiveCoverageGainOverSafeK1Interval95: [number, number];
} {
  const byCase = new Map<string, CasePolicyDecision[]>();
  for (const record of records) {
    const list = byCase.get(record.caseId) ?? [];
    list.push(record);
    byCase.set(record.caseId, list);
  }
  const caseIds = [...byCase.keys()].sort();
  const rng = mulberry32(seed);
  const adaptiveValues: number[] = [];
  const gainValues: number[] = [];

  for (let draw = 0; draw < draws; draw += 1) {
    const sampled: CasePolicyDecision[] = [];
    for (let index = 0; index < caseIds.length; index += 1) {
      const caseId = caseIds[Math.floor(rng() * caseIds.length)];
      sampled.push(...(byCase.get(caseId) ?? []));
    }
    const metrics = aggregateMetrics(sampled);
    adaptiveValues.push(metrics.adaptiveSafeCoverage);
    gainValues.push(metrics.adaptiveCoverageGainOverSafeK1);
  }

  return {
    method: "case-clustered-percentile",
    seed,
    draws,
    adaptiveSafeCoverageInterval95: [percentile(adaptiveValues, 0.025), percentile(adaptiveValues, 0.975)],
    adaptiveCoverageGainOverSafeK1Interval95: [percentile(gainValues, 0.025), percentile(gainValues, 0.975)],
  };
}

function perKCoverage(
  rows: readonly PredictionVectorRow[],
  policies: readonly WaggleDecisionPolicy[],
  probabilityScale: number,
  maxK: number
): Array<{ k: number; safeCoverage: number; continues: number; denominator: number }> {
  const results = [];
  for (let k = 1; k <= maxK; k += 1) {
    let continues = 0;
    let denominator = 0;
    for (const row of rows) {
      for (const policy of policies) {
        const full = referenceDecision(row.probabilities, probabilityScale, policy);
        if (full.disposition !== "continue") continue;
        denominator += 1;
        const certificate = createDecisionCertificate({
          caseId: row.caseId,
          probabilities: row.probabilities,
          probabilityScale,
          policy,
          maxRevealed: k,
        });
        if (certificate.disposition === "continue" && certificate.actionId === full.actionId) {
          continues += 1;
        }
      }
    }
    results.push({
      k,
      safeCoverage: denominator === 0 ? 0 : continues / denominator,
      continues,
      denominator,
    });
  }
  return results;
}

function perPolicyCoverage(
  records: readonly CasePolicyDecision[],
  policySeeds: readonly number[]
): Array<{
  policySeed: number;
  policyId: string;
  adaptiveSafeCoverage: number;
  safeK1Coverage: number;
  safeK3Coverage: number;
  denominator: number;
}> {
  return policySeeds.map((seed) => {
    const subset = records.filter((record) => record.policySeed === seed);
    const metrics = aggregateMetrics(subset);
    return {
      policySeed: seed,
      policyId: subset[0]?.policyId ?? "",
      adaptiveSafeCoverage: metrics.adaptiveSafeCoverage,
      safeK1Coverage: metrics.safeK1Coverage,
      safeK3Coverage: metrics.safeK3Coverage,
      denominator: metrics.fullVectorNonTiedDenominator,
    };
  });
}

function recomputePrimaryGates(
  config: DecisionSufficiencyConfig,
  metrics: {
    adaptiveSafeCoverage: number;
    safeK1Coverage: number;
    adaptiveDecisionMismatches: number;
    fullVectorDecisionMismatches: number;
    expectedCostSummaryDecisionMismatches: number;
    naiveTop1DecisionMismatches: number;
    noStateContinues: number;
    attacksRejected: boolean;
    authorityGrants: number;
    providerApiCalls: number;
    modelApiCalls: number;
    authorityEffects: number;
  }
): {
  scientificVerdict: "H1_TASK_SUFFICIENCY_SUPPORTED" | "H0_RETAINED";
  gates: Record<string, boolean>;
} {
  const admission = config.primaryAdmission;
  const gates = {
    adaptiveSafeCoverage:
      metrics.adaptiveSafeCoverage >= admission.adaptiveSafeCoverageMinimum,
    adaptiveCoverageGainOverSafeK1:
      metrics.adaptiveSafeCoverage - metrics.safeK1Coverage >=
      admission.adaptiveCoverageGainOverSafeK1Minimum,
    adaptiveDecisionMismatches:
      metrics.adaptiveDecisionMismatches <= admission.adaptiveDecisionMismatchesMaximum,
    fullVectorDecisionMismatches:
      metrics.fullVectorDecisionMismatches <= admission.fullVectorDecisionMismatchesMaximum,
    expectedCostSummaryDecisionMismatches:
      metrics.expectedCostSummaryDecisionMismatches <=
      admission.expectedCostSummaryDecisionMismatchesMaximum,
    naiveTop1DecisionMismatches:
      metrics.naiveTop1DecisionMismatches >= admission.naiveTop1DecisionMismatchesMinimum,
    noStateContinues: metrics.noStateContinues <= admission.noStateContinuesMaximum,
    attacksRejected: metrics.attacksRejected === true && metrics.authorityGrants === 0,
    zeroEffects:
      metrics.providerApiCalls === 0 &&
      metrics.modelApiCalls === 0 &&
      metrics.authorityEffects === 0,
  };
  const admitted = Object.values(gates).every(Boolean);
  return {
    scientificVerdict: admitted ? "H1_TASK_SUFFICIENCY_SUPPORTED" : "H0_RETAINED",
    gates,
  };
}

// ---------------------------------------------------------------------------
// Attack probes (fail-closed)
// ---------------------------------------------------------------------------

function runAttackProbes(input: {
  certificate: WaggleDecisionCertificate;
  policy: WaggleDecisionPolicy;
  probabilities: readonly number[];
}): {
  schemaVersion: typeof ATTACKS_SCHEMA;
  authorityGranted: false;
  allSpecifiedTampersRejected: boolean;
  falseAccepts: number;
  cases: Array<{ name: string; rejected: boolean; authorityGranted: false }>;
} {
  const cases: Array<{ name: string; rejected: boolean; authorityGranted: false }> = [];

  const push = (name: string, rejected: boolean, _detail?: string) => {
    cases.push({ name, rejected, authorityGranted: false });
  };

  // Altered residual.
  {
    const tampered = structuredClone(input.certificate);
    tampered.residualUnits = Math.max(0, tampered.residualUnits - 1);
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("forged_residual", errors.length > 0, errors[0] ?? "accepted");
  }

  // Reordered / invalid revealed ranking.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.revealed.length >= 2) {
      [tampered.revealed[0], tampered.revealed[1]] = [tampered.revealed[1], tampered.revealed[0]];
    } else {
      tampered.revealed[0] = {
        index: (tampered.revealed[0].index + 1) % tampered.sourceProbabilityCount,
        probabilityUnits: tampered.revealed[0].probabilityUnits,
      };
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("reordered_or_invalid_revealed", errors.length > 0, errors[0] ?? "accepted");
  }

  // Duplicate indices.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.revealed.length >= 1) {
      tampered.revealed = [
        tampered.revealed[0],
        {
          ...tampered.revealed[0],
          probabilityUnits: Math.max(0, tampered.revealed[0].probabilityUnits - 1),
        },
      ];
      tampered.residualUnits =
        tampered.probabilityScale -
        tampered.revealed.reduce((sum, item) => sum + item.probabilityUnits, 0);
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("duplicate_revealed_index", errors.length > 0, errors[0] ?? "accepted");
  }

  // Forged action.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.actionId) {
      tampered.actionId =
        input.policy.actionIds.find((id) => id !== tampered.actionId) ?? tampered.actionId;
    } else {
      tampered.disposition = "continue";
      tampered.actionId = input.policy.actionIds[0];
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("forged_action", errors.length > 0, errors[0] ?? "accepted");
  }

  // Forged bound.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.pairwiseLowerAdvantages.length > 0) {
      tampered.pairwiseLowerAdvantages[0].lowerAdvantageUnits += 1;
    } else {
      tampered.pairwiseLowerAdvantages = [
        { opponentActionId: input.policy.actionIds[0], lowerAdvantageUnits: 1 },
      ];
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("forged_bound", errors.length > 0, errors[0] ?? "accepted");
  }

  // Policy drift.
  {
    const drifted = structuredClone(input.policy);
    drifted.policyId = `decisionpolicy_${"0".repeat(20)}`;
    const errors = verifyDecisionCertificateMath(input.certificate, drifted);
    push("policy_drift", errors.length > 0, errors[0] ?? "accepted");
  }

  // Vector ID drift via qualification.
  {
    const wrongVector = [...input.probabilities];
    const donor = wrongVector.findIndex((value) => value > 0);
    const recipient = donor === 0 ? 1 : 0;
    requireCondition(donor >= 0 && recipient < wrongVector.length, "vector drift fixture unavailable");
    wrongVector[donor] -= 1;
    wrongVector[recipient] += 1;
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: wrongVector,
    });
    push(
      "vector_id_drift",
      qualification.disposition === "rejected",
      qualification.errors[0] ?? "accepted"
    );
  }

  // Rehashed certificate id.
  {
    const tampered = structuredClone(input.certificate);
    tampered.certificateId = `decisioncert_${"0".repeat(20)}`;
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("rehashed_certificate_id", errors.length > 0, errors[0] ?? "accepted");
  }

  // Fully rehashed semantic certificate forgery.
  {
    const tampered = structuredClone(input.certificate);
    tampered.actionId =
      input.policy.actionIds.find((id) => id !== tampered.actionId) ?? input.policy.actionIds[0];
    const { certificateId: _oldId, ...body } = tampered;
    tampered.certificateId = contentId("decisioncert", body);
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("rehashed_semantic_certificate", errors.length > 0, errors[0] ?? "accepted");
  }

  // Authority smuggling on qualification.
  {
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: input.probabilities,
    });
    const forged = structuredClone(qualification) as KeaDecisionQualification & {
      authorityGranted: boolean;
    };
    forged.authorityGranted = true;
    const consumer = consumeQualifiedDecision({
      certificate: input.certificate,
      policy: input.policy,
      qualification: forged as KeaDecisionQualification,
    });
    push(
      "authority_smuggling",
      consumer.disposition === "abstain" && consumer.authorityGranted === false,
      consumer.disposition
    );
  }

  // Unknown fields.
  {
    const tampered = {
      ...structuredClone(input.certificate),
      unexpectedField: true,
    } as WaggleDecisionCertificate & { unexpectedField: boolean };
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("unknown_fields", errors.length > 0, errors[0] ?? "accepted");
  }

  // Non-integer / negative mass.
  {
    const tampered = structuredClone(input.certificate);
    tampered.residualUnits = -1;
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("non_integer_or_negative_mass", errors.length > 0, errors[0] ?? "accepted");
  }

  // Qualification rehash.
  {
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: input.probabilities,
    });
    const forged = structuredClone(qualification);
    forged.qualificationId = `keaqualification_${"0".repeat(20)}`;
    const consumer = consumeQualifiedDecision({
      certificate: input.certificate,
      policy: input.policy,
      qualification: forged,
    });
    push("rehashed_qualification", consumer.disposition === "abstain", consumer.disposition);
  }

  // Fully rehashed semantic qualification forgery still cannot cause continuation.
  {
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: input.probabilities,
    });
    const forged = structuredClone(qualification);
    forged.referenceDecisionMatched = false;
    const { qualificationId: _oldId, ...body } = forged;
    forged.qualificationId = contentId("keaqualification", body);
    const consumer = consumeQualifiedDecision({
      certificate: input.certificate,
      policy: input.policy,
      qualification: forged,
    });
    push(
      "rehashed_semantic_qualification",
      consumer.disposition === "abstain" && consumer.authorityGranted === false,
      consumer.disposition
    );
  }

  // Noncanonical qualification fields fail closed in the restricted consumer.
  {
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: input.probabilities,
    });
    const forged = { ...qualification, unexpectedField: true };
    const consumer = consumeQualifiedDecision({
      certificate: input.certificate,
      policy: input.policy,
      qualification: forged as KeaDecisionQualification,
    });
    push("unknown_qualification_field", consumer.disposition === "abstain", consumer.disposition);
  }

  // Altered probability mass on certificate revealed units without residual repair.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.revealed.length > 0) {
      tampered.revealed[0] = {
        ...tampered.revealed[0],
        probabilityUnits: tampered.revealed[0].probabilityUnits + 1,
      };
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("altered_probability_mass", errors.length > 0, errors[0] ?? "accepted");
  }

  const falseAccepts = cases.filter((item) => !item.rejected).length;
  return {
    schemaVersion: ATTACKS_SCHEMA,
    authorityGranted: false,
    allSpecifiedTampersRejected: falseAccepts === 0,
    falseAccepts,
    cases,
  };
}

// ---------------------------------------------------------------------------
// Sample selection
// ---------------------------------------------------------------------------

function selectSampleCaseIds(caseIds: readonly string[], count: number): string[] {
  return [...caseIds]
    .sort((left, right) => sha256(left).localeCompare(sha256(right)))
    .slice(0, Math.min(count, caseIds.length));
}

// ---------------------------------------------------------------------------
// Full evaluation
// ---------------------------------------------------------------------------

function loadPredictionState(inputDir: string): {
  labels: string[];
  vectors: PredictionVectorRow[];
  run: Record<string, unknown>;
  environment: Record<string, unknown> | null;
} {
  requireCondition(existsSync(inputDir), `input directory missing: ${inputDir}`);
  const entries = readdirSync(inputDir);
  for (const name of entries) {
    const path = join(inputDir, name);
    if (lstatSync(path).isSymbolicLink()) {
      throw new Error(`input contains symlink (rejected): ${name}`);
    }
  }

  const runPath = join(inputDir, "run.json");
  const vectorsPath = join(inputDir, "vectors.jsonl");
  requireCondition(existsSync(runPath), "run.json is required");
  requireCondition(existsSync(vectorsPath), "vectors.jsonl is required");

  const run = readJson<Record<string, unknown>>(runPath);
  const environment = existsSync(join(inputDir, "environment.json"))
    ? readJson<Record<string, unknown>>(join(inputDir, "environment.json"))
    : null;

  const model = (run.model ?? {}) as Record<string, unknown>;
  const labelsFromRun = (model.labelIds ?? run.labelIds ?? run.labels) as string[] | undefined;
  const labelsPath = join(inputDir, "labels.json");
  let labels = labelsFromRun
    ?? (existsSync(labelsPath) ? readJson<{ labelIds: string[] }>(labelsPath).labelIds : null);

  const rawVectors = readFileSync(vectorsPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PredictionVectorRow);

  requireCondition(rawVectors.length > 0, "vectors.jsonl is empty");
  if ((!labels || labels.length < 2) && Array.isArray(rawVectors[0].labelIds)) {
    labels = rawVectors[0].labelIds as string[];
  }
  requireCondition(Array.isArray(labels) && labels.length >= 2, "label inventory missing from prediction state");

  for (const row of rawVectors) {
    requireCondition(typeof row.caseId === "string" && row.caseId.length > 0, "vector caseId invalid");
    requireCondition(Array.isArray(row.probabilities), "vector probabilities missing");
    requireCondition(row.probabilities.length === labels.length, "vector length does not match labels");
    requireCondition(row.sourceSplit === "test", "vector sourceSplit drifted");
    requireCondition(Number.isSafeInteger(row.sourceIndex), "vector sourceIndex invalid");
    requireCondition(typeof row.modelId === "string" && row.modelId.length > 0, "vector modelId invalid");
    requireCondition(
      Array.isArray(row.labelIds) && canonicalJson(row.labelIds) === canonicalJson(labels),
      "vector labelIds drifted"
    );
    requireCondition(row.textIncluded !== true, "source text must be excluded from prediction state");
    requireCondition(!("text" in row), "source text leaked into prediction state");
    requireCondition(!("sourceText" in row), "source text leaked into prediction state");
    requireCondition(!("utterance" in row), "source text leaked into prediction state");
  }

  return { labels, vectors: rawVectors, run, environment };
}

function evaluateFull(config: DecisionSufficiencyConfig, inputDir: string, outputDir: string): void {
  const { labels, vectors: rawVectors, run, environment: inputEnvironment } = loadPredictionState(inputDir);
  const probabilityScale = config.probabilityScale;
  const labelIds = labels.map(wireLabel);
  const runId = run.runId;
  requireCondition(typeof runId === "string" && /^decisionrun_[a-f0-9]{20}$/.test(runId), "runId invalid");
  const { runId: _ignoredRunId, ...runBody } = run;
  requireCondition(runId === contentId("decisionrun", runBody), "runId does not match run content");
  const runnerVectorArtifact = run.vectorArtifact as { rows?: number; sha256?: string } | undefined;
  requireCondition(runnerVectorArtifact?.rows === rawVectors.length, "runner vector row count drifted");
  requireCondition(
    runnerVectorArtifact?.sha256 === sha256(readFileSync(join(inputDir, "vectors.jsonl"))),
    "runner vector digest drifted"
  );
  const continuity = classifierContinuity(rawVectors, labels, config.continuityReference);

  // Preserve the runner's text-free vector rows exactly so run.json continues to bind them.
  const vectors: Array<{
    schemaVersion: typeof VECTOR_SCHEMA;
    caseId: string;
    vectorId: string;
    probabilityScale: number;
    probabilities: number[];
    trueIntent: string;
    sourceSplit: string;
    sourceIndex: number;
    modelId: string;
    labelIds: string[];
    textIncluded: false;
  }> = rawVectors.map((row) => {
    const sum = row.probabilities.reduce((total, value) => total + value, 0);
    requireCondition(sum === probabilityScale, `vector ${row.caseId} mass ${sum} != ${probabilityScale}`);
    const observedId = decisionVectorId(row.probabilities, probabilityScale);
    if (row.vectorId) {
      requireCondition(row.vectorId === observedId, `vectorId drift for ${row.caseId}`);
    }
    return {
      schemaVersion: VECTOR_SCHEMA,
      caseId: row.caseId,
      vectorId: observedId,
      probabilityScale,
      probabilities: row.probabilities,
      trueIntent: (() => {
        requireCondition(typeof row.trueIntent === "string", `trueIntent missing for ${row.caseId}`);
        return row.trueIntent;
      })(),
      sourceSplit: String(row.sourceSplit),
      sourceIndex: Number(row.sourceIndex),
      modelId: String(row.modelId),
      labelIds: [...(row.labelIds as string[])],
      textIncluded: false as const,
    };
  });

  const policies = derivePolicies(config, labelIds);
  const policySeeds = config.policyFamily.seeds;
  const records: CasePolicyDecision[] = [];

  for (const row of vectors) {
    for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
      records.push(
        evaluateCasePolicy({
          caseId: row.caseId,
          probabilities: row.probabilities,
          probabilityScale,
          policy: policies[policyIndex],
          policySeed: policySeeds[policyIndex],
          maxRevealed: config.maxRevealedProbabilities,
          vectorId: row.vectorId,
          measureTransport: true,
        })
      );
    }
  }

  const metricsCore = aggregateMetrics(records);

  const probeRow = vectors[0];
  const probePolicy = policies[0];
  const probeCertificate = createDecisionCertificate({
    caseId: probeRow.caseId,
    probabilities: probeRow.probabilities,
    probabilityScale,
    policy: probePolicy,
    maxRevealed: config.maxRevealedProbabilities,
  });
  const attacks = runAttackProbes({
    certificate: probeCertificate,
    policy: probePolicy,
    probabilities: probeRow.probabilities,
  });

  const bootstrap = caseClusteredBootstrap(
    records,
    config.bootstrap.seed,
    config.bootstrap.draws
  );

  const sampleCaseIds = selectSampleCaseIds(
    vectors.map((row) => row.caseId),
    config.certificateSampleCases
  );
  const firstPolicyId = policies[0].policyId;
  // Sample order is deterministic SHA-256(caseId) order, not caseId locale order.
  const samples = sampleCaseIds.map((caseId) => {
    const record = records.find(
      (item) => item.caseId === caseId && item.policyId === firstPolicyId
    );
    requireCondition(record !== undefined, `missing sample decision for ${caseId}`);
    return {
      schemaVersion: SAMPLE_SCHEMA,
      caseId: record.caseId,
      policyId: record.policyId,
      textIncluded: false as const,
      certificate: record.adaptive.certificate,
      qualification: record.qualification,
      restricted: record.restricted,
      authorityGranted: false as const,
    };
  });

  // Secondary quantities required by PROTOCOL are committed below, not left on stdout only.
  const certificateBytes = records.map((record) => record.bytes.certificate);
  const fullVectorBytes = records.map((record) => record.bytes.fullVector);
  const expectedCostSummaryBytes = records.map((record) => record.bytes.expectedCostSummary);
  const qualificationBytes = records.map((record) => record.bytes.qualification);
  const wagglePacketBytes = records.map((record) => record.bytes.wagglePacket);
  const waggleMessageBytes = records.map((record) => record.bytes.waggleMessageEnvelope);
  const ledgerBytes = records.map((record) => record.bytes.ledger);
  const revealedCounts = records.map((record) => record.adaptive.certificate.revealed.length);
  const perK = perKCoverage(vectors, policies, probabilityScale, config.maxRevealedProbabilities);
  const perPolicy = perPolicyCoverage(records, policySeeds);
  const refusalCounts = {
    adaptiveInsufficientConfidence: records.filter(
      (record) => record.adaptive.certificate.disposition === "insufficient_confidence"
    ).length,
    fullVectorInsufficientConfidence: records.filter(
      (record) => record.fullVector.disposition === "insufficient_confidence"
    ).length,
    safeK1InsufficientConfidence: records.filter(
      (record) => record.safeK1.certificate.disposition === "insufficient_confidence"
    ).length,
    safeK3InsufficientConfidence: records.filter(
      (record) => record.safeK3.certificate.disposition === "insufficient_confidence"
    ).length,
  };
  const parity = {
    adaptiveActionMatchesFullVector: records.filter(
      (record) =>
        record.adaptive.certificate.disposition === "continue" &&
        record.adaptive.certificate.actionId === record.fullVector.actionId
    ).length,
    adaptiveContinues: metricsCore.adaptiveSafeContinues,
    keaQualificationParity: records.filter(
      (record) =>
        record.qualification.disposition === "qualified" ||
        record.qualification.disposition === "abstained"
    ).length,
    restrictedConsumerParity: records.filter(
      (record) =>
        record.restricted.disposition === "continue" ||
        record.restricted.disposition === "insufficient_confidence"
    ).length,
  };

  const effects = {
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffectsExecuted: 0,
  };

  const primary = recomputePrimaryGates(config, {
    adaptiveSafeCoverage: metricsCore.adaptiveSafeCoverage,
    safeK1Coverage: metricsCore.safeK1Coverage,
    adaptiveDecisionMismatches: metricsCore.adaptiveDecisionMismatches,
    fullVectorDecisionMismatches: metricsCore.fullVectorDecisionMismatches,
    expectedCostSummaryDecisionMismatches:
      metricsCore.expectedCostSummaryDecisionMismatches,
    naiveTop1DecisionMismatches: metricsCore.naiveTop1DecisionMismatches,
    noStateContinues: metricsCore.noStateContinues,
    attacksRejected: attacks.allSpecifiedTampersRejected && attacks.falseAccepts === 0,
    authorityGrants: 0,
    providerApiCalls: effects.providerApiCalls,
    modelApiCalls: effects.modelApiCalls,
    authorityEffects: effects.authorityEffectsExecuted,
  });

  // Frozen evaluation inventory keys (exact surface verified independently).
  const evaluation = {
    schemaVersion: EVALUATION_SCHEMA,
    status: "preregistered-prospective-secondary-analysis",
    authorityGranted: false as const,
    caseCount: vectors.length,
    decisionCount: records.length,
    sampleCount: samples.length,
    metrics: {
      adaptiveSafeCoverage: metricsCore.adaptiveSafeCoverage,
      safeK1Coverage: metricsCore.safeK1Coverage,
      safeK3Coverage: metricsCore.safeK3Coverage,
      adaptiveDecisionMismatches: metricsCore.adaptiveDecisionMismatches,
      fullVectorDecisionMismatches: metricsCore.fullVectorDecisionMismatches,
      expectedCostSummaryDecisionMismatches:
        metricsCore.expectedCostSummaryDecisionMismatches,
      naiveTop1DecisionMismatches: metricsCore.naiveTop1DecisionMismatches,
      noStateContinues: metricsCore.noStateContinues,
      fullVectorNonTiedDenominator: metricsCore.fullVectorNonTiedDenominator,
      adaptiveSafeContinues: metricsCore.adaptiveSafeContinues,
      safeK1Continues: metricsCore.safeK1Continues,
      safeK3Continues: metricsCore.safeK3Continues,
      adaptiveCoverageGainOverSafeK1: metricsCore.adaptiveCoverageGainOverSafeK1,
    },
    bootstrap,
    perK,
    perPolicy,
    refusals: refusalCounts,
    parity,
    revealedComponents: summarizeIntegers(revealedCounts),
    classifierContinuity: continuity,
    bytes: {
      unit: "canonical UTF-8 bytes; not tokens, cost, memory, energy, or total resources",
      fullVector: summarizeIntegers(fullVectorBytes),
      certificate: summarizeIntegers(certificateBytes),
      expectedCostSummary: summarizeIntegers(expectedCostSummaryBytes),
      qualification: summarizeIntegers(qualificationBytes),
      wagglePacket: summarizeIntegers(wagglePacketBytes),
      waggleMessageEnvelope: summarizeIntegers(waggleMessageBytes),
      ledger: summarizeIntegers(ledgerBytes),
    },
    nonClaims: [
      "The result is a preregistered prospective secondary analysis, not an independent model replication.",
      "A first certifying top-probability prefix is not a globally minimum message.",
      "The expected-cost summary is an equally informed compact control and may be smaller.",
      "Bytes are not tokens, credits, cost, memory, energy, or overall efficiency.",
      "No privacy, security against a permitted malicious writer, production, or authority is established.",
    ],
    primaryGates: primary.gates,
    scientificVerdict: primary.scientificVerdict,
    effects,
  };

  const environment = {
    schemaVersion: ENVIRONMENT_SCHEMA,
    status: "preregistered-prospective-secondary-analysis",
    runner: inputEnvironment,
    evaluator: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffectsExecuted: 0,
    scoredPhaseNetworkCalls: 0,
  };

  const policiesArtifact = {
    schemaVersion: POLICIES_SCHEMA,
    labelIds,
    policies,
  };

  // Full certificate rows are gzip-compressed deterministically; readable samples remain separate.
  const decisionRows = records.map((record) => ({
    schemaVersion: record.schemaVersion,
    caseId: record.caseId,
    policyId: record.policyId,
    vectorId: record.vectorId,
    authorityGranted: false as const,
    fullVector: record.fullVector,
    fullVectorReconstruction: record.fullVectorReconstruction,
    expectedCostSummary: record.expectedCostSummary,
    adaptive: record.adaptive,
    safeK1: record.safeK1,
    safeK3: record.safeK3,
    naiveTop1: record.naiveTop1,
    noState: record.noState,
    qualification: {
      disposition: record.qualification.disposition,
      qualificationId: record.qualification.qualificationId,
      authorityGranted: false as const,
    },
    restricted: {
      disposition: record.restricted.disposition,
      actionId: record.restricted.actionId,
      authorityGranted: false as const,
    },
    bytes: record.bytes,
  }));

  mkdirSync(outputDir, { recursive: true, mode: 0o755 });
  writeCanonicalJson(join(outputDir, "environment.json"), environment);
  writeCanonicalJson(join(outputDir, "run.json"), run);
  writeCanonicalJson(join(outputDir, "policies.json"), policiesArtifact);
  writeCanonicalJson(join(outputDir, "evaluation.json"), evaluation);
  writeCanonicalJson(join(outputDir, "attacks.json"), attacks);
  writeJsonl(join(outputDir, "vectors.jsonl"), vectors);
  const decisionPayload = Buffer.from(
    `${decisionRows.map((row) => canonicalJson(row)).join("\n")}\n`,
    "utf8"
  );
  writeFileSync(join(outputDir, "decisions.jsonl.gz"), gzipSync(decisionPayload, { level: 9 }));
  writeJsonl(join(outputDir, "samples.jsonl"), samples);

  const checksumLines = [...REQUIRED_ARTIFACTS]
    .sort()
    .map((name) => `${sha256(readFileSync(join(outputDir, name)))}  ${name}`);
  writeFileSync(join(outputDir, "SHA256SUMS"), `${checksumLines.join("\n")}\n`, "utf8");

  console.log(
    JSON.stringify({
      ok: true,
      scientificVerdict: primary.scientificVerdict,
      cases: vectors.length,
      decisionCount: records.length,
      sampleCount: samples.length,
      adaptiveSafeCoverage: metricsCore.adaptiveSafeCoverage,
      adaptiveCoverageGainOverSafeK1: metricsCore.adaptiveCoverageGainOverSafeK1,
      primaryGates: primary.gates,
      bootstrap,
      perK,
      perPolicy,
      refusals: refusalCounts,
      parity,
      bytes: evaluation.bytes,
      effects,
      attacksRejected: attacks.allSpecifiedTampersRejected,
      inputEnvironmentPresent: inputEnvironment !== null,
      output: outputDir,
    })
  );
}

// ---------------------------------------------------------------------------
// Synthetic self-test (no BANKING77, no scored outputs)
// ---------------------------------------------------------------------------

function runSelfTest(config: DecisionSufficiencyConfig): void {
  const scale = 1_000_000;
  // Wide synthetic inventory so four-action SHA-256 partitions occupy every action.
  const wideLabels = Array.from({ length: 32 }, (_, index) => `label_${index}`);

  // Policy determinism: same seed+labels always yields identical policyId and matrix.
  const singleSeedConfig: DecisionSufficiencyConfig = {
    ...config,
    policyFamily: {
      ...config.policyFamily,
      seeds: [config.policyFamily.seeds[0]],
    },
  };
  const policiesA = derivePolicies(singleSeedConfig, wideLabels);
  const policiesB = derivePolicies(singleSeedConfig, wideLabels);
  requireCondition(policiesA.length === 1 && policiesB.length === 1, "self-test policy count");
  requireCondition(policiesA[0].policyId === policiesB[0].policyId, "policy determinism failed");
  requireCondition(
    canonicalJson(policiesA[0].costMatrix) === canonicalJson(policiesB[0].costMatrix),
    "policy matrix determinism failed"
  );
  requireCondition(
    assignActionIndex(config.policyFamily.seeds[0], wideLabels[0], 4) ===
      assignActionIndex(config.policyFamily.seeds[0], wideLabels[0], 4),
    "action assignment must be deterministic"
  );
  // Separator contract: SHA-256(`${seed}:${labelId}`) — not pipe.
  const colonDigest = createHash("sha256")
    .update(`${config.policyFamily.seeds[0]}:${wideLabels[0]}`, "utf8")
    .digest()
    .readUInt32BE(0) % 4;
  requireCondition(
    assignActionIndex(config.policyFamily.seeds[0], wideLabels[0], 4) === colonDigest,
    "policy assignment must use seed:labelId"
  );

  // Full 12-policy family occupies every action on the synthetic inventory.
  const twelve = derivePolicies(config, wideLabels);
  requireCondition(twelve.length === 12, "expected 12 policies");
  for (const policy of twelve) {
    for (let actionIndex = 0; actionIndex < policy.actionIds.length; actionIndex += 1) {
      const occupied = policy.costMatrix[actionIndex].some(
        (cost) => cost === config.policyFamily.matchCostUnits
      );
      requireCondition(occupied, `policy ${policy.policyId} left an action empty`);
    }
  }

  // Compact two-action fixture policy for continuation / refusal / naive mismatch.
  const labelIds = ["label_a", "label_b", "label_c", "label_d"];
  const fixturePolicy = createDecisionPolicy({
    labelIds,
    actionIds: ["queue_left", "queue_right"],
    costMatrix: [
      [0, 0, 1_000, 1_000],
      [1_000, 1_000, 0, 0],
    ],
  });

  // 1) Continuation with adaptive certificate, Kea qualification, and restricted consumer.
  const continuationVector = [700_000, 100_000, 100_000, 100_000];
  const continuationRecord = evaluateCasePolicy({
    caseId: "case_self_continue",
    probabilities: continuationVector,
    probabilityScale: scale,
    policy: fixturePolicy,
    policySeed: config.policyFamily.seeds[0],
    maxRevealed: 3,
    vectorId: decisionVectorId(continuationVector, scale),
    measureTransport: true,
  });
  requireCondition(
    continuationRecord.adaptive.certificate.disposition === "continue",
    "expected continuation"
  );
  requireCondition(
    continuationRecord.adaptive.certificate.actionId === "queue_left",
    "continuation action mismatch"
  );
  requireCondition(
    continuationRecord.adaptive.certificate.authorityGranted === false,
    "certificate authority must be false"
  );
  requireCondition(
    continuationRecord.qualification.disposition === "qualified",
    "expected qualified disposition"
  );
  requireCondition(
    continuationRecord.qualification.authorityGranted === false,
    "qualification authority must be false"
  );
  requireCondition(
    continuationRecord.restricted.disposition === "continue",
    "consumer should continue"
  );
  requireCondition(
    continuationRecord.restricted.actionId === "queue_left",
    "consumer action mismatch"
  );
  requireCondition(
    continuationRecord.restricted.authorityGranted === false,
    "consumer authority must be false"
  );
  requireCondition(
    continuationRecord.fullVectorReconstruction.vectorId === continuationRecord.vectorId &&
      continuationRecord.fullVectorReconstruction.actionId === continuationRecord.fullVector.actionId,
    "canonical full-vector round trip failed"
  );
  requireCondition(
    continuationRecord.expectedCostSummary.actionId === continuationRecord.fullVector.actionId &&
      continuationRecord.expectedCostSummary.authorityGranted === false,
    "expected-cost summary parity failed"
  );

  // 2) Insufficient-confidence refusal (unresolved residual interval).
  const refusalVector = [300_000, 200_000, 300_000, 200_000];
  const refusalRecord = evaluateCasePolicy({
    caseId: "case_self_refuse",
    probabilities: refusalVector,
    probabilityScale: scale,
    policy: fixturePolicy,
    policySeed: config.policyFamily.seeds[0],
    maxRevealed: 3,
    vectorId: decisionVectorId(refusalVector, scale),
    measureTransport: false,
  });
  requireCondition(
    refusalRecord.adaptive.certificate.disposition === "insufficient_confidence",
    "expected insufficient_confidence refusal"
  );
  requireCondition(
    refusalRecord.adaptive.certificate.actionId === null,
    "refusal must not emit an action"
  );
  requireCondition(
    refusalRecord.qualification.disposition === "abstained",
    "expected abstained qualification"
  );
  requireCondition(
    refusalRecord.restricted.disposition === "insufficient_confidence",
    "consumer should refuse with insufficient_confidence"
  );
  requireCondition(
    refusalRecord.restricted.authorityGranted === false,
    "refusal authority must be false"
  );

  // 3) Naive top-1 control can mismatch the full-vector min-cost action.
  const naiveMismatchPolicy = createDecisionPolicy({
    labelIds: ["l0", "l1", "l2", "l3"],
    actionIds: ["left", "right"],
    costMatrix: [
      [0, 0, 1_000, 1_000],
      [1_000, 1_000, 0, 0],
    ],
  });
  // Top-1 is l2 (right), but combined left mass 0.55 > right mass 0.45 → full vector chooses left.
  const naiveVector = [300_000, 250_000, 400_000, 50_000];
  const full = referenceDecision(naiveVector, scale, naiveMismatchPolicy);
  const naive = naiveTop1Action(naiveVector, naiveMismatchPolicy);
  requireCondition(full.disposition === "continue", "naive-mismatch fixture full vector must continue");
  requireCondition(naive.disposition === "continue", "naive-mismatch fixture naive must continue");
  requireCondition(full.actionId !== naive.actionId, "expected naive-control mismatch");
  requireCondition(full.actionId === "left", "full vector should select left");
  requireCondition(naive.actionId === "right", "naive top-1 should select right");

  // Byte boundary helpers are finite and positive.
  requireCondition(continuationRecord.bytes.certificate > 0, "certificate bytes");
  requireCondition(continuationRecord.bytes.fullVector > 0, "full-vector bytes");
  requireCondition(continuationRecord.bytes.qualification > 0, "qualification bytes");
  requireCondition(continuationRecord.bytes.expectedCostSummary > 0, "expected-cost-summary bytes");
  requireCondition(continuationRecord.bytes.wagglePacket > 0, "waggle packet bytes");
  requireCondition(continuationRecord.bytes.ledger > 0, "ledger bytes");

  // Attack probe smoke: every specified tamper rejected, no authority.
  const attacks = runAttackProbes({
    certificate: continuationRecord.adaptive.certificate,
    policy: fixturePolicy,
    probabilities: continuationVector,
  });
  requireCondition(attacks.falseAccepts === 0, `attack false accepts: ${JSON.stringify(attacks.cases)}`);
  requireCondition(attacks.allSpecifiedTampersRejected === true, "attack suite incomplete");
  requireCondition(attacks.authorityGranted === false, "attack artifact must not grant authority");

  // Primary admission rule is pure (no expected-result constants baked into the gate function).
  const hold = recomputePrimaryGates(config, {
    adaptiveSafeCoverage: 0.95,
    safeK1Coverage: 0.8,
    adaptiveDecisionMismatches: 0,
    fullVectorDecisionMismatches: 0,
    expectedCostSummaryDecisionMismatches: 0,
    naiveTop1DecisionMismatches: 1,
    noStateContinues: 0,
    attacksRejected: true,
    authorityGrants: 0,
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffects: 0,
  });
  requireCondition(
    hold.scientificVerdict === "H1_TASK_SUFFICIENCY_SUPPORTED",
    "admission rule should admit a passing metric bundle"
  );
  const retain = recomputePrimaryGates(config, {
    adaptiveSafeCoverage: 0.5,
    safeK1Coverage: 0.5,
    adaptiveDecisionMismatches: 0,
    fullVectorDecisionMismatches: 0,
    expectedCostSummaryDecisionMismatches: 0,
    naiveTop1DecisionMismatches: 1,
    noStateContinues: 0,
    attacksRejected: true,
    authorityGrants: 0,
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffects: 0,
  });
  requireCondition(retain.scientificVerdict === "H0_RETAINED", "admission rule should retain H0 on failed coverage");

  // No-state control never continues.
  requireCondition(continuationRecord.noState.disposition !== "continue", "no-state must not continue");
  requireCondition(continuationRecord.noState.actionId === null, "no-state must not emit action");
  requireCondition(continuationRecord.authorityGranted === false, "decision authority must be false");

  console.log("EVALUATOR_SELF_TEST_OK");
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const config = readJson<DecisionSufficiencyConfig>(resolve(args.config));
  requireCondition(
    config.schemaVersion === "waggle.decision-sufficiency.config.v1",
    "config schemaVersion drift"
  );
  requireCondition(config.probabilityScale === 1_000_000, "probabilityScale drift");
  requireCondition(config.maxRevealedProbabilities === 8, "maxRevealedProbabilities drift");
  requireCondition(
    canonicalJson(config.fixedSafeControls) === canonicalJson([1, 3]),
    "fixedSafeControls drift"
  );
  requireCondition(config.policyFamily.seeds.length === 12, "frozen config requires exactly 12 policy seeds");
  requireCondition(
    config.policyFamily.type === "sha256-partitioned-four-action-zero-one-cost",
    "policy family type drift"
  );
  requireCondition(
    config.primaryAdmission.expectedCostSummaryDecisionMismatchesMaximum === 0,
    "expected-cost-summary gate drift"
  );
  requireCondition(
    config.continuityReference.maximumAbsoluteDrift === 1e-12,
    "classifier continuity policy drift"
  );

  if (args.selfTest) {
    runSelfTest(config);
    return;
  }

  requireCondition(typeof args.input === "string" && args.input.length > 0, "--input is required in full mode");
  evaluateFull(config, resolve(args.input), resolve(args.output));
}

main();
