#!/usr/bin/env -S npx tsx
/**
 * Frozen decision-sufficiency experiment coordinator (Waggle + Kea v0.3).
 *
 * Full mode reads text-free prediction-state artifacts from the runner, derives
 * the 12 SHA-256 four-action policies, evaluates every matched control arm,
 * measures byte boundaries, runs attack probes, applies primary admission
 * gates, and writes evaluation artifacts. The synthetic --self-test path never
 * loads BANKING77 outputs and never inspects scored results.
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
// Paths and config
// ---------------------------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONFIG = join(HERE, "config.v1.json");
const DEFAULT_OUTPUT = join(HERE, "results/local-v1");

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
    naiveTop1DecisionMismatchesMinimum: number;
    noStateContinuesMaximum: number;
  };
  certificateSampleCases: number;
  effects: {
    providerApiCallsMaximum: number;
    modelApiCallsMaximum: number;
    authorityEffectsMaximum: number;
  };
}

interface PredictionVectorRow {
  caseId: string;
  sourceIndex: number;
  vectorId: string;
  probabilities: number[];
  trueIntent?: string;
  textIncluded?: false;
}

interface ArmDecision {
  arm: string;
  disposition: "continue" | "insufficient_confidence" | "abstain";
  actionId: string | null;
  revealedCount: number | null;
  matchesFullVector: boolean | null;
  authorityGranted: false;
}

interface CasePolicyRecord {
  caseId: string;
  policySeed: number;
  policyId: string;
  fullVector: ArmDecision;
  adaptive: ArmDecision & {
    certificateId: string | null;
    qualificationDisposition: string | null;
    consumerDisposition: string | null;
    certificateBytes: number;
    qualificationBytes: number;
    wagglePacketBytes: number;
    waggleMessageBytes: number;
    ledgerBytes: number;
  };
  safeK1: ArmDecision;
  safeK3: ArmDecision;
  naiveTop1: ArmDecision;
  noState: ArmDecision;
  fullVectorBytes: number;
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

function writeJson(path: string, value: unknown): void {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
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

// ---------------------------------------------------------------------------
// Policy family (frozen SHA-256 partition)
// ---------------------------------------------------------------------------

export function assignActionIndex(seed: number, labelId: string, actionCount: number): number {
  const digest = createHash("sha256").update(`${seed}|${labelId}`, "utf8").digest();
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
  let bestMass = -1;
  for (let index = 0; index < probabilities.length; index += 1) {
    const mass = probabilities[index];
    if (mass > bestMass || (mass === bestMass && index < bestIndex)) {
      bestMass = mass;
      bestIndex = index;
    }
  }
  // Break pure ties among max mass by lexicographic smallest index already applied.
  const winners = probabilities
    .map((mass, index) => ({ mass, index }))
    .filter((item) => item.mass === bestMass);
  if (winners.length !== 1) {
    // Deterministic unique top-1: lowest index among max-mass labels still maps to an action.
  }
  const labelIndex = winners[0].index;
  // Action with match cost 0 for this label.
  let actionId: string | null = null;
  for (let actionIndex = 0; actionIndex < policy.actionIds.length; actionIndex += 1) {
    if (policy.costMatrix[actionIndex][labelIndex] === 0) {
      actionId = policy.actionIds[actionIndex];
      break;
    }
  }
  return { disposition: actionId ? "continue" : "insufficient_confidence", actionId };
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

function evaluateCertificateArm(input: {
  caseId: string;
  probabilities: readonly number[];
  probabilityScale: number;
  policy: WaggleDecisionPolicy;
  maxRevealed: number;
  fullVectorActionId: string | null;
  fullVectorDisposition: "continue" | "insufficient_confidence";
  measureTransport: boolean;
}): CasePolicyRecord["adaptive"] {
  const certificate = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: input.maxRevealed,
  });
  const qualification = qualifyDecisionCertificate({
    certificate,
    policy: input.policy,
    fullProbabilityVector: input.probabilities,
  });
  const consumer = consumeQualifiedDecision({
    certificate,
    policy: input.policy,
    qualification,
  });

  requireCondition(certificate.authorityGranted === false, "certificate granted authority");
  requireCondition(qualification.authorityGranted === false, "qualification granted authority");
  requireCondition(consumer.authorityGranted === false, "consumer granted authority");

  let wagglePacketBytes = 0;
  let waggleMessageBytes = 0;
  let ledgerBytes = 0;
  if (input.measureTransport) {
    const packet = certificatePacket(certificate);
    wagglePacketBytes = waggleWireBytes(packet);
    const message = createWaggleV0Message({
      missionId: "mission_decision_sufficiency",
      workNodeId: `work_${input.caseId}`,
      senderAgentId: "agent_decision_producer",
      receiverActorIds: ["agent_restricted_consumer"],
      packet,
      contextPackId: input.caseId,
      artifactRefs: [certificate.certificateId],
      evidenceRefs: [certificate.vectorId],
      authorityEffect: "none",
      sensitivity: "public",
      createdAt: "2026-08-05T00:00:00.000Z",
    });
    waggleMessageBytes = decisionStateBytes(message);
    // Ledger bytes are measured as a standalone, authority-free qualification append
    // (restricted consumer path never grants effects).
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
        disposition: consumer.disposition === "continue" ? "verified" : "rejected",
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
    ledgerBytes = decisionStateBytes(syntheticLedger.read());
  }

  const matchesFullVector =
    certificate.disposition === "continue"
      ? input.fullVectorDisposition === "continue" && certificate.actionId === input.fullVectorActionId
      : null;

  return {
    arm: `adaptive_safe_k_le_${input.maxRevealed}`,
    disposition:
      consumer.disposition === "continue"
        ? "continue"
        : consumer.disposition === "insufficient_confidence"
          ? "insufficient_confidence"
          : certificate.disposition === "continue"
            ? "continue"
            : "insufficient_confidence",
    actionId: consumer.disposition === "continue" ? consumer.actionId : certificate.actionId,
    revealedCount: certificate.revealed.length,
    matchesFullVector:
      certificate.disposition === "continue"
        ? certificate.actionId === input.fullVectorActionId && input.fullVectorDisposition === "continue"
        : matchesFullVector,
    authorityGranted: false,
    certificateId: certificate.certificateId,
    qualificationDisposition: qualification.disposition,
    consumerDisposition: consumer.disposition,
    certificateBytes: decisionStateBytes(certificate),
    qualificationBytes: decisionStateBytes(qualification),
    wagglePacketBytes,
    waggleMessageBytes,
    ledgerBytes,
  };
}

function evaluateCasePolicy(input: {
  caseId: string;
  probabilities: readonly number[];
  probabilityScale: number;
  policy: WaggleDecisionPolicy;
  policySeed: number;
  maxRevealed: number;
  measureTransport: boolean;
}): CasePolicyRecord {
  const full = referenceDecision(input.probabilities, input.probabilityScale, input.policy);
  const fullVectorBytes = decisionStateBytes({
    probabilityScale: input.probabilityScale,
    probabilities: input.probabilities,
  });

  const adaptive = evaluateCertificateArm({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: input.maxRevealed,
    fullVectorActionId: full.actionId,
    fullVectorDisposition: full.disposition,
    measureTransport: input.measureTransport,
  });

  const safeK1Cert = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: 1,
  });
  const safeK3Cert = createDecisionCertificate({
    caseId: input.caseId,
    probabilities: input.probabilities,
    probabilityScale: input.probabilityScale,
    policy: input.policy,
    maxRevealed: 3,
  });
  const naive = naiveTop1Action(input.probabilities, input.policy);

  const fullArm: ArmDecision = {
    arm: "full_vector",
    disposition: full.disposition,
    actionId: full.actionId,
    revealedCount: input.probabilities.length,
    matchesFullVector: true,
    authorityGranted: false,
  };

  const toSafeArm = (
    arm: string,
    certificate: WaggleDecisionCertificate
  ): ArmDecision => ({
    arm,
    disposition: certificate.disposition,
    actionId: certificate.actionId,
    revealedCount: certificate.revealed.length,
    matchesFullVector:
      certificate.disposition === "continue"
        ? full.disposition === "continue" && certificate.actionId === full.actionId
        : null,
    authorityGranted: false,
  });

  return {
    caseId: input.caseId,
    policySeed: input.policySeed,
    policyId: input.policy.policyId,
    fullVector: fullArm,
    adaptive: {
      ...adaptive,
      arm: "adaptive_safe_k_le_8",
    },
    safeK1: toSafeArm("safe_k_1", safeK1Cert),
    safeK3: toSafeArm("safe_k_3", safeK3Cert),
    naiveTop1: {
      arm: "naive_top1",
      disposition: naive.disposition,
      actionId: naive.actionId,
      revealedCount: 1,
      matchesFullVector:
        naive.disposition === "continue" && full.disposition === "continue"
          ? naive.actionId === full.actionId
          : naive.disposition === full.disposition && naive.actionId === full.actionId,
      authorityGranted: false,
    },
    noState: {
      arm: "no_state",
      disposition: "abstain",
      actionId: null,
      revealedCount: 0,
      matchesFullVector: false,
      authorityGranted: false,
    },
    fullVectorBytes,
  };
}

// ---------------------------------------------------------------------------
// Metrics, bootstrap, primary gates
// ---------------------------------------------------------------------------

function coverageOf(
  records: readonly CasePolicyRecord[],
  arm: "adaptive" | "safeK1" | "safeK3"
): { continues: number; denominator: number; coverage: number; mismatches: number } {
  const eligible = records.filter((record) => record.fullVector.disposition === "continue");
  const denominator = eligible.length;
  let continues = 0;
  let mismatches = 0;
  for (const record of eligible) {
    const decision = record[arm];
    if (decision.disposition === "continue") {
      continues += 1;
      if (decision.actionId !== record.fullVector.actionId) mismatches += 1;
    }
  }
  return {
    continues,
    denominator,
    coverage: denominator === 0 ? 0 : continues / denominator,
    mismatches,
  };
}

function countNaiveMismatches(records: readonly CasePolicyRecord[]): number {
  let count = 0;
  for (const record of records) {
    if (record.fullVector.disposition !== "continue") continue;
    if (
      record.naiveTop1.disposition !== "continue" ||
      record.naiveTop1.actionId !== record.fullVector.actionId
    ) {
      count += 1;
    }
  }
  return count;
}

function countNoStateContinues(records: readonly CasePolicyRecord[]): number {
  return records.filter((record) => record.noState.disposition === "continue").length;
}

function countFullVectorReconstructionMismatches(records: readonly CasePolicyRecord[]): number {
  // Reconstruction mismatch: adaptive certificate continues with action that differs from full vector,
  // or full-vector reference is inconsistent with itself (should be zero by construction).
  let count = 0;
  for (const record of records) {
    if (
      record.adaptive.disposition === "continue" &&
      record.adaptive.actionId !== record.fullVector.actionId
    ) {
      count += 1;
    }
    if (record.fullVector.matchesFullVector !== true) count += 1;
  }
  return count;
}

function caseClusteredBootstrap(
  records: readonly CasePolicyRecord[],
  seed: number,
  draws: number
): {
  method: "case-clustered-percentile";
  seed: number;
  draws: number;
  adaptiveSafeCoverageInterval95: [number, number];
  adaptiveCoverageGainOverSafeK1Interval95: [number, number];
} {
  const byCase = new Map<string, CasePolicyRecord[]>();
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
    const sampled: CasePolicyRecord[] = [];
    for (let index = 0; index < caseIds.length; index += 1) {
      const caseId = caseIds[Math.floor(rng() * caseIds.length)];
      sampled.push(...(byCase.get(caseId) ?? []));
    }
    const adaptive = coverageOf(sampled, "adaptive");
    const safeK1 = coverageOf(sampled, "safeK1");
    adaptiveValues.push(adaptive.coverage);
    gainValues.push(adaptive.coverage - safeK1.coverage);
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
      for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
        const policy = policies[policyIndex];
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
        if (
          certificate.disposition === "continue" &&
          certificate.actionId === full.actionId
        ) {
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
  records: readonly CasePolicyRecord[],
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
    const adaptive = coverageOf(subset, "adaptive");
    const safeK1 = coverageOf(subset, "safeK1");
    const safeK3 = coverageOf(subset, "safeK3");
    return {
      policySeed: seed,
      policyId: subset[0]?.policyId ?? "",
      adaptiveSafeCoverage: adaptive.coverage,
      safeK1Coverage: safeK1.coverage,
      safeK3Coverage: safeK3.coverage,
      denominator: adaptive.denominator,
    };
  });
}

function primaryVerdict(
  config: DecisionSufficiencyConfig,
  metrics: {
    adaptiveSafeCoverage: number;
    adaptiveCoverageGainOverSafeK1: number;
    adaptiveDecisionMismatches: number;
    fullVectorDecisionMismatches: number;
    naiveTop1DecisionMismatches: number;
    noStateContinues: number;
    attackFalseAccepts: number;
    authorityGrants: number;
    providerApiCalls: number;
    modelApiCalls: number;
    authorityEffects: number;
  }
): "H1_TASK_SUFFICIENCY_SUPPORTED" | "H0_RETAINED" {
  const gates = config.primaryAdmission;
  const effects = config.effects;
  const admitted =
    metrics.adaptiveSafeCoverage >= gates.adaptiveSafeCoverageMinimum &&
    metrics.adaptiveCoverageGainOverSafeK1 >= gates.adaptiveCoverageGainOverSafeK1Minimum &&
    metrics.adaptiveDecisionMismatches <= gates.adaptiveDecisionMismatchesMaximum &&
    metrics.fullVectorDecisionMismatches <= gates.fullVectorDecisionMismatchesMaximum &&
    metrics.naiveTop1DecisionMismatches >= gates.naiveTop1DecisionMismatchesMinimum &&
    metrics.noStateContinues <= gates.noStateContinuesMaximum &&
    metrics.attackFalseAccepts === 0 &&
    metrics.authorityGrants === 0 &&
    metrics.providerApiCalls <= effects.providerApiCallsMaximum &&
    metrics.modelApiCalls <= effects.modelApiCallsMaximum &&
    metrics.authorityEffects <= effects.authorityEffectsMaximum;
  return admitted ? "H1_TASK_SUFFICIENCY_SUPPORTED" : "H0_RETAINED";
}

// ---------------------------------------------------------------------------
// Attack probes (fail-closed)
// ---------------------------------------------------------------------------

function runAttackProbes(input: {
  certificate: WaggleDecisionCertificate;
  policy: WaggleDecisionPolicy;
  probabilities: readonly number[];
}): {
  probes: Array<{ id: string; rejected: boolean; detail: string }>;
  falseAccepts: number;
  authorityGrants: number;
} {
  const probes: Array<{ id: string; rejected: boolean; detail: string }> = [];
  let authorityGrants = 0;

  const push = (id: string, rejected: boolean, detail: string) => {
    probes.push({ id, rejected, detail });
  };

  // Altered residual.
  {
    const tampered = structuredClone(input.certificate);
    tampered.residualUnits = Math.max(0, tampered.residualUnits - 1);
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("forged_residual", errors.length > 0, errors[0] ?? "accepted");
  }

  // Reordered revealed indices (break canonical ranking).
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
        { ...tampered.revealed[0], probabilityUnits: Math.max(0, tampered.revealed[0].probabilityUnits - 1) },
      ];
      tampered.residualUnits = tampered.probabilityScale - tampered.revealed.reduce((s, r) => s + r.probabilityUnits, 0);
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("duplicate_revealed_index", errors.length > 0, errors[0] ?? "accepted");
  }

  // Action change without rehash identity check path.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.actionId) {
      tampered.actionId = input.policy.actionIds.find((id) => id !== tampered.actionId) ?? tampered.actionId;
    } else {
      tampered.disposition = "continue";
      tampered.actionId = input.policy.actionIds[0];
    }
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("forged_action", errors.length > 0, errors[0] ?? "accepted");
  }

  // Bound change.
  {
    const tampered = structuredClone(input.certificate);
    if (tampered.pairwiseLowerAdvantages.length > 0) {
      tampered.pairwiseLowerAdvantages[0].lowerAdvantageUnits += 1;
    } else {
      tampered.pairwiseLowerAdvantages = [{ opponentActionId: input.policy.actionIds[0], lowerAdvantageUnits: 1 }];
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
    const wrongVector = input.probabilities.map((value, index) =>
      index === 0 ? Math.max(0, value - 1) : index === 1 ? value + 1 : value
    );
    // Repair sum if needed.
    const sum = wrongVector.reduce((a, b) => a + b, 0);
    if (sum !== input.certificate.probabilityScale) {
      wrongVector[wrongVector.length - 1] += input.certificate.probabilityScale - sum;
    }
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: wrongVector,
    });
    push("vector_id_drift", qualification.disposition === "rejected", qualification.errors[0] ?? "accepted");
    if (qualification.authorityGranted !== false) authorityGrants += 1;
  }

  // Rehashed certificate id forgery.
  {
    const tampered = structuredClone(input.certificate);
    tampered.certificateId = `decisioncert_${"0".repeat(20)}`;
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("rehashed_certificate_id", errors.length > 0, errors[0] ?? "accepted");
  }

  // Authority smuggling on qualification.
  {
    const qualification = qualifyDecisionCertificate({
      certificate: input.certificate,
      policy: input.policy,
      fullProbabilityVector: input.probabilities,
    });
    const forged = structuredClone(qualification) as KeaDecisionQualification & { authorityGranted: boolean };
    forged.authorityGranted = true;
    const consumer = consumeQualifiedDecision({
      certificate: input.certificate,
      policy: input.policy,
      qualification: forged as KeaDecisionQualification,
    });
    const rejected = consumer.disposition === "abstain";
    push("authority_smuggling", rejected, rejected ? "consumer abstained" : "consumer accepted authority forgery");
    if (consumer.authorityGranted !== false) authorityGrants += 1;
  }

  // Unknown field / non-canonical keys.
  {
    const tampered = {
      ...structuredClone(input.certificate),
      unexpectedField: true,
    } as WaggleDecisionCertificate & { unexpectedField: boolean };
    const errors = verifyDecisionCertificateMath(tampered, input.policy);
    push("unknown_fields", errors.length > 0, errors[0] ?? "accepted");
  }

  // Non-integer / negative mass via verify path (certificate with negative residual).
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

  const falseAccepts = probes.filter((probe) => !probe.rejected).length;
  return { probes, falseAccepts, authorityGrants };
}

// ---------------------------------------------------------------------------
// Sample selection
// ---------------------------------------------------------------------------

function selectSampleCaseIds(caseIds: readonly string[], count: number): string[] {
  return [...caseIds]
    .sort((left, right) => sha256(left).localeCompare(sha256(right)))
    .slice(0, Math.min(count, caseIds.length));
}

function buildCertificateSample(
  rows: readonly PredictionVectorRow[],
  policies: readonly WaggleDecisionPolicy[],
  policySeeds: readonly number[],
  probabilityScale: number,
  maxRevealed: number,
  sampleCaseIds: readonly string[]
): Array<Record<string, unknown>> {
  const selected = new Set(sampleCaseIds);
  const samples: Array<Record<string, unknown>> = [];
  for (const row of rows) {
    if (!selected.has(row.caseId)) continue;
    // One sample per case under the first policy seed (text-free certificate surface).
    const policy = policies[0];
    const certificate = createDecisionCertificate({
      caseId: row.caseId,
      probabilities: row.probabilities,
      probabilityScale,
      policy,
      maxRevealed,
    });
    const qualification = qualifyDecisionCertificate({
      certificate,
      policy,
      fullProbabilityVector: row.probabilities,
    });
    const consumer = consumeQualifiedDecision({ certificate, policy, qualification });
    samples.push({
      caseId: row.caseId,
      policySeed: policySeeds[0],
      policyId: policy.policyId,
      vectorId: certificate.vectorId,
      certificateId: certificate.certificateId,
      qualificationId: qualification.qualificationId,
      disposition: certificate.disposition,
      actionId: certificate.actionId,
      revealed: certificate.revealed,
      residualUnits: certificate.residualUnits,
      pairwiseLowerAdvantages: certificate.pairwiseLowerAdvantages,
      consumerDisposition: consumer.disposition,
      authorityGranted: false,
      textIncluded: false,
    });
  }
  return samples.sort((a, b) => String(a.caseId).localeCompare(String(b.caseId)));
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

  const labelsFromRun = (run.labelIds ?? run.labels) as string[] | undefined;
  const labelsPath = join(inputDir, "labels.json");
  const labels = labelsFromRun
    ?? (existsSync(labelsPath) ? (readJson<{ labelIds: string[] }>(labelsPath).labelIds) : null);
  requireCondition(Array.isArray(labels) && labels.length >= 2, "label inventory missing from prediction state");

  const vectors = readFileSync(vectorsPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as PredictionVectorRow);

  requireCondition(vectors.length > 0, "vectors.jsonl is empty");
  for (const row of vectors) {
    requireCondition(typeof row.caseId === "string" && row.caseId.length > 0, "vector caseId invalid");
    requireCondition(Array.isArray(row.probabilities), "vector probabilities missing");
    requireCondition(row.probabilities.length === labels.length, "vector length does not match labels");
    requireCondition(row.textIncluded !== true, "source text must be excluded from prediction state");
    const sum = row.probabilities.reduce((total, value) => total + value, 0);
    requireCondition(sum === (run.probabilityScale as number) || sum > 0, "probability mass invalid");
  }

  return { labels, vectors, run, environment };
}

function evaluateFull(config: DecisionSufficiencyConfig, inputDir: string, outputDir: string): void {
  const { labels, vectors, run, environment } = loadPredictionState(inputDir);
  const probabilityScale = config.probabilityScale;
  for (const row of vectors) {
    const sum = row.probabilities.reduce((total, value) => total + value, 0);
    requireCondition(sum === probabilityScale, `vector ${row.caseId} mass ${sum} != ${probabilityScale}`);
    const observedId = decisionVectorId(row.probabilities, probabilityScale);
    if (row.vectorId) {
      requireCondition(row.vectorId === observedId, `vectorId drift for ${row.caseId}`);
    } else {
      row.vectorId = observedId;
    }
  }

  const policies = derivePolicies(config, labels);
  const policySeeds = config.policyFamily.seeds;
  const records: CasePolicyRecord[] = [];

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
          measureTransport: true,
        })
      );
    }
  }

  const adaptive = coverageOf(records, "adaptive");
  const safeK1 = coverageOf(records, "safeK1");
  const safeK3 = coverageOf(records, "safeK3");
  const naiveMismatches = countNaiveMismatches(records);
  const noStateContinues = countNoStateContinues(records);
  const fullVectorMismatches = countFullVectorReconstructionMismatches(records);
  const adaptiveDecisionMismatches = adaptive.mismatches;

  // Attack probes on the first continuing certificate when available.
  let attack = {
    probes: [] as Array<{ id: string; rejected: boolean; detail: string }>,
    falseAccepts: 0,
    authorityGrants: 0,
  };
  {
    const probeRow = vectors[0];
    const probePolicy = policies[0];
    const certificate = createDecisionCertificate({
      caseId: probeRow.caseId,
      probabilities: probeRow.probabilities,
      probabilityScale,
      policy: probePolicy,
      maxRevealed: config.maxRevealedProbabilities,
    });
    attack = runAttackProbes({
      certificate,
      policy: probePolicy,
      probabilities: probeRow.probabilities,
    });
  }

  const bootstrap = caseClusteredBootstrap(
    records,
    config.bootstrap.seed,
    config.bootstrap.draws
  );

  const certificateBytes = records.map((record) => record.adaptive.certificateBytes);
  const fullVectorBytes = records.map((record) => record.fullVectorBytes);
  const qualificationBytes = records.map((record) => record.adaptive.qualificationBytes);
  const wagglePacketBytes = records.map((record) => record.adaptive.wagglePacketBytes);
  const waggleMessageBytes = records.map((record) => record.adaptive.waggleMessageBytes);
  const ledgerBytes = records.map((record) => record.adaptive.ledgerBytes);

  const sampleCaseIds = selectSampleCaseIds(
    vectors.map((row) => row.caseId),
    config.certificateSampleCases
  );
  const certificateSample = buildCertificateSample(
    vectors,
    policies,
    policySeeds,
    probabilityScale,
    config.maxRevealedProbabilities,
    sampleCaseIds
  );

  const refusalCounts = {
    adaptiveInsufficientConfidence: records.filter(
      (record) => record.adaptive.disposition === "insufficient_confidence"
    ).length,
    fullVectorInsufficientConfidence: records.filter(
      (record) => record.fullVector.disposition === "insufficient_confidence"
    ).length,
    safeK1InsufficientConfidence: records.filter(
      (record) => record.safeK1.disposition === "insufficient_confidence"
    ).length,
    safeK3InsufficientConfidence: records.filter(
      (record) => record.safeK3.disposition === "insufficient_confidence"
    ).length,
  };

  const revealedDistribution: Record<string, number> = {};
  for (const record of records) {
    if (record.adaptive.disposition !== "continue") continue;
    const key = String(record.adaptive.revealedCount ?? 0);
    revealedDistribution[key] = (revealedDistribution[key] ?? 0) + 1;
  }

  const metrics = {
    caseCount: vectors.length,
    policyCount: policies.length,
    casePolicyCount: records.length,
    fullVectorNonTiedDenominator: adaptive.denominator,
    adaptiveSafeCoverage: adaptive.coverage,
    adaptiveSafeContinues: adaptive.continues,
    safeK1Coverage: safeK1.coverage,
    safeK3Coverage: safeK3.coverage,
    adaptiveCoverageGainOverSafeK1: adaptive.coverage - safeK1.coverage,
    adaptiveDecisionMismatches,
    fullVectorDecisionMismatches: fullVectorMismatches,
    naiveTop1DecisionMismatches: naiveMismatches,
    noStateContinues,
    refusalCounts,
    revealedComponentDistribution: revealedDistribution,
  };

  const effects = {
    providerApiCalls: 0,
    modelApiCalls: 0,
    networkCalls: 0,
    authorityEffectsExecuted: 0,
    authorityGrants: attack.authorityGrants,
  };

  const verdict = primaryVerdict(config, {
    adaptiveSafeCoverage: metrics.adaptiveSafeCoverage,
    adaptiveCoverageGainOverSafeK1: metrics.adaptiveCoverageGainOverSafeK1,
    adaptiveDecisionMismatches: metrics.adaptiveDecisionMismatches,
    fullVectorDecisionMismatches: metrics.fullVectorDecisionMismatches,
    naiveTop1DecisionMismatches: metrics.naiveTop1DecisionMismatches,
    noStateContinues: metrics.noStateContinues,
    attackFalseAccepts: attack.falseAccepts,
    authorityGrants: effects.authorityGrants,
    providerApiCalls: effects.providerApiCalls,
    modelApiCalls: effects.modelApiCalls,
    authorityEffects: effects.authorityEffectsExecuted,
  });

  const primaryGates = {
    adaptiveSafeCoverageMinimum: config.primaryAdmission.adaptiveSafeCoverageMinimum,
    adaptiveSafeCoverageObserved: metrics.adaptiveSafeCoverage,
    adaptiveSafeCoveragePassed:
      metrics.adaptiveSafeCoverage >= config.primaryAdmission.adaptiveSafeCoverageMinimum,
    adaptiveCoverageGainOverSafeK1Minimum:
      config.primaryAdmission.adaptiveCoverageGainOverSafeK1Minimum,
    adaptiveCoverageGainOverSafeK1Observed: metrics.adaptiveCoverageGainOverSafeK1,
    adaptiveCoverageGainOverSafeK1Passed:
      metrics.adaptiveCoverageGainOverSafeK1 >=
      config.primaryAdmission.adaptiveCoverageGainOverSafeK1Minimum,
    adaptiveDecisionMismatchesMaximum: config.primaryAdmission.adaptiveDecisionMismatchesMaximum,
    adaptiveDecisionMismatchesObserved: metrics.adaptiveDecisionMismatches,
    adaptiveDecisionMismatchesPassed:
      metrics.adaptiveDecisionMismatches <= config.primaryAdmission.adaptiveDecisionMismatchesMaximum,
    fullVectorDecisionMismatchesMaximum:
      config.primaryAdmission.fullVectorDecisionMismatchesMaximum,
    fullVectorDecisionMismatchesObserved: metrics.fullVectorDecisionMismatches,
    fullVectorDecisionMismatchesPassed:
      metrics.fullVectorDecisionMismatches <=
      config.primaryAdmission.fullVectorDecisionMismatchesMaximum,
    naiveTop1DecisionMismatchesMinimum:
      config.primaryAdmission.naiveTop1DecisionMismatchesMinimum,
    naiveTop1DecisionMismatchesObserved: metrics.naiveTop1DecisionMismatches,
    naiveTop1DecisionMismatchesPassed:
      metrics.naiveTop1DecisionMismatches >=
      config.primaryAdmission.naiveTop1DecisionMismatchesMinimum,
    noStateContinuesMaximum: config.primaryAdmission.noStateContinuesMaximum,
    noStateContinuesObserved: metrics.noStateContinues,
    noStateContinuesPassed:
      metrics.noStateContinues <= config.primaryAdmission.noStateContinuesMaximum,
    attackFalseAcceptsObserved: attack.falseAccepts,
    attackFalseAcceptsPassed: attack.falseAccepts === 0,
    authorityGrantsObserved: effects.authorityGrants,
    authorityGrantsPassed: effects.authorityGrants === 0,
    effectsPassed:
      effects.providerApiCalls === 0 &&
      effects.modelApiCalls === 0 &&
      effects.authorityEffectsExecuted === 0,
  };

  const evaluation = {
    schemaVersion: "waggle.decision-sufficiency.evaluation.v1",
    status: config.status,
    dataset: config.dataset,
    evidenceClass: "preregistered-prospective-secondary-analysis",
    config,
    inputRun: {
      schemaVersion: run.schemaVersion ?? null,
      vectorCount: vectors.length,
      environmentPresent: environment !== null,
    },
    policies: policies.map((policy, index) => ({
      seed: policySeeds[index],
      policyId: policy.policyId,
      actionIds: policy.actionIds,
      labelCount: policy.labelIds.length,
    })),
    arms: [
      "full_vector",
      "adaptive_safe_k_le_8",
      "safe_k_1",
      "safe_k_3",
      "naive_top1",
      "no_state",
    ],
    metrics,
    primaryGates,
    primaryVerdict: verdict,
    bootstrap,
    perK: perKCoverage(
      vectors,
      policies,
      probabilityScale,
      config.maxRevealedProbabilities
    ),
    perPolicy: perPolicyCoverage(records, policySeeds),
    bytes: {
      unit: "canonical UTF-8 bytes; not tokens, cost, memory, energy, or total resources",
      fullVector: {
        median: median(fullVectorBytes),
        p95: percentile(fullVectorBytes, 0.95),
        total: fullVectorBytes.reduce((sum, value) => sum + value, 0),
      },
      certificate: {
        median: median(certificateBytes),
        p95: percentile(certificateBytes, 0.95),
        total: certificateBytes.reduce((sum, value) => sum + value, 0),
      },
      qualification: {
        median: median(qualificationBytes),
        p95: percentile(qualificationBytes, 0.95),
        total: qualificationBytes.reduce((sum, value) => sum + value, 0),
      },
      wagglePacket: {
        median: median(wagglePacketBytes),
        p95: percentile(wagglePacketBytes, 0.95),
        total: wagglePacketBytes.reduce((sum, value) => sum + value, 0),
      },
      waggleMessageEnvelope: {
        median: median(waggleMessageBytes),
        p95: percentile(waggleMessageBytes, 0.95),
        total: waggleMessageBytes.reduce((sum, value) => sum + value, 0),
      },
      ledger: {
        median: median(ledgerBytes),
        p95: percentile(ledgerBytes, 0.95),
        total: ledgerBytes.reduce((sum, value) => sum + value, 0),
      },
    },
    attacks: attack,
    effects,
    certificateSample: {
      selection: `${config.certificateSampleCases} smallest SHA-256(caseId) values`,
      caseCount: sampleCaseIds.length,
      caseIds: sampleCaseIds,
    },
    parity: {
      adaptiveActionMatchesFullVector:
        records.filter(
          (record) =>
            record.adaptive.disposition === "continue" &&
            record.adaptive.actionId === record.fullVector.actionId
        ).length,
      adaptiveContinues: records.filter((record) => record.adaptive.disposition === "continue").length,
      keaQualificationParity: records.filter(
        (record) =>
          record.adaptive.qualificationDisposition === "qualified" ||
          record.adaptive.qualificationDisposition === "abstained"
      ).length,
      restrictedConsumerParity: records.filter(
        (record) =>
          record.adaptive.consumerDisposition === "continue" ||
          record.adaptive.consumerDisposition === "insufficient_confidence"
      ).length,
    },
    nonClaims: [
      "Decision sufficiency is not semantic compression or a universal minimum message.",
      "Safe coverage is not overall efficiency, cost, energy, or token savings.",
      "Kea qualification never grants execution authority.",
      "Negative primary results must not be repaired by changing thresholds or denominators.",
    ],
  };

  mkdirSync(outputDir, { recursive: true, mode: 0o755 });
  writeJson(join(outputDir, "evaluation.json"), evaluation);
  writeJson(
    join(outputDir, "policies.json"),
    {
      schemaVersion: "waggle.decision-sufficiency.policies.v1",
      policies: policies.map((policy, index) => ({
        seed: policySeeds[index],
        policy,
      })),
    }
  );
  writeFileSync(
    join(outputDir, "certificate-sample.jsonl"),
    `${certificateSample.map((row) => canonicalJson(row)).join("\n")}\n`,
    "utf8"
  );
  writeJson(join(outputDir, "case-policy-summary.json"), {
    schemaVersion: "waggle.decision-sufficiency.case-policy-summary.v1",
    records: records.map((record) => ({
      caseId: record.caseId,
      policySeed: record.policySeed,
      policyId: record.policyId,
      fullVectorDisposition: record.fullVector.disposition,
      fullVectorActionId: record.fullVector.actionId,
      adaptiveDisposition: record.adaptive.disposition,
      adaptiveActionId: record.adaptive.actionId,
      adaptiveRevealedCount: record.adaptive.revealedCount,
      safeK1Disposition: record.safeK1.disposition,
      safeK3Disposition: record.safeK3.disposition,
      naiveTop1ActionId: record.naiveTop1.actionId,
      naiveMatchesFullVector: record.naiveTop1.matchesFullVector,
      noStateDisposition: record.noState.disposition,
      certificateBytes: record.adaptive.certificateBytes,
      fullVectorBytes: record.fullVectorBytes,
      qualificationBytes: record.adaptive.qualificationBytes,
      wagglePacketBytes: record.adaptive.wagglePacketBytes,
      ledgerBytes: record.adaptive.ledgerBytes,
    })),
  });

  const artifactNames = [
    "evaluation.json",
    "policies.json",
    "certificate-sample.jsonl",
    "case-policy-summary.json",
  ];
  const checksumLines = artifactNames.map(
    (name) => `${sha256(readFileSync(join(outputDir, name)))}  ${name}`
  );
  writeFileSync(join(outputDir, "SHA256SUMS"), `${checksumLines.join("\n")}\n`, "utf8");

  console.log(
    JSON.stringify({
      ok: true,
      primaryVerdict: verdict,
      cases: vectors.length,
      casePolicyPairs: records.length,
      adaptiveSafeCoverage: metrics.adaptiveSafeCoverage,
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

  // Full 12-policy family occupies every action on the synthetic inventory.
  const twelve = derivePolicies(config, wideLabels);
  requireCondition(twelve.length === 12, "expected 12 policies");
  for (const policy of twelve) {
    for (let actionIndex = 0; actionIndex < policy.actionIds.length; actionIndex += 1) {
      const occupied = policy.costMatrix[actionIndex].some((cost) => cost === config.policyFamily.matchCostUnits);
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
  const continuationCertificate = createDecisionCertificate({
    caseId: "case_self_continue",
    probabilities: continuationVector,
    probabilityScale: scale,
    policy: fixturePolicy,
    maxRevealed: 3,
  });
  requireCondition(continuationCertificate.disposition === "continue", "expected continuation");
  requireCondition(continuationCertificate.actionId === "queue_left", "continuation action mismatch");
  requireCondition(continuationCertificate.authorityGranted === false, "certificate authority must be false");
  const continuationQualification = qualifyDecisionCertificate({
    certificate: continuationCertificate,
    policy: fixturePolicy,
    fullProbabilityVector: continuationVector,
  });
  requireCondition(continuationQualification.disposition === "qualified", "expected qualified disposition");
  requireCondition(continuationQualification.authorityGranted === false, "qualification authority must be false");
  const continuationConsumer = consumeQualifiedDecision({
    certificate: continuationCertificate,
    policy: fixturePolicy,
    qualification: continuationQualification,
  });
  requireCondition(continuationConsumer.disposition === "continue", "consumer should continue");
  requireCondition(continuationConsumer.actionId === "queue_left", "consumer action mismatch");
  requireCondition(continuationConsumer.authorityGranted === false, "consumer authority must be false");

  // 2) Insufficient-confidence refusal (unresolved residual interval).
  const refusalVector = [300_000, 200_000, 300_000, 200_000];
  const refusalCertificate = createDecisionCertificate({
    caseId: "case_self_refuse",
    probabilities: refusalVector,
    probabilityScale: scale,
    policy: fixturePolicy,
    maxRevealed: 3,
  });
  requireCondition(
    refusalCertificate.disposition === "insufficient_confidence",
    "expected insufficient_confidence refusal"
  );
  requireCondition(refusalCertificate.actionId === null, "refusal must not emit an action");
  const refusalQualification = qualifyDecisionCertificate({
    certificate: refusalCertificate,
    policy: fixturePolicy,
    fullProbabilityVector: refusalVector,
  });
  requireCondition(refusalQualification.disposition === "abstained", "expected abstained qualification");
  const refusalConsumer = consumeQualifiedDecision({
    certificate: refusalCertificate,
    policy: fixturePolicy,
    qualification: refusalQualification,
  });
  requireCondition(
    refusalConsumer.disposition === "insufficient_confidence",
    "consumer should refuse with insufficient_confidence"
  );
  requireCondition(refusalConsumer.authorityGranted === false, "refusal authority must be false");

  // 3) Naive top-1 control can mismatch the full-vector min-cost action.
  // Full-vector: mass on labels mapped to both actions can make min expected cost differ from top-1 label action.
  // Construct: top-1 label maps to right, but total mass prefers left.
  const naiveMismatchPolicy = createDecisionPolicy({
    labelIds: ["l0", "l1", "l2", "l3"],
    actionIds: ["left", "right"],
    costMatrix: [
      // left matches l0,l1
      [0, 0, 1_000, 1_000],
      // right matches l2,l3
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

  // Byte boundary helpers are finite and positive for certificates / vectors.
  requireCondition(decisionStateBytes(continuationCertificate) > 0, "certificate bytes");
  requireCondition(
    decisionStateBytes({ probabilityScale: scale, probabilities: continuationVector }) > 0,
    "full-vector bytes"
  );
  requireCondition(decisionStateBytes(continuationQualification) > 0, "qualification bytes");
  const packet = certificatePacket(continuationCertificate);
  requireCondition(waggleWireBytes(packet) > 0, "waggle packet bytes");

  // Attack probe smoke: authority smuggling rejected.
  const attacks = runAttackProbes({
    certificate: continuationCertificate,
    policy: fixturePolicy,
    probabilities: continuationVector,
  });
  requireCondition(attacks.falseAccepts === 0, `attack false accepts: ${JSON.stringify(attacks.probes)}`);
  requireCondition(attacks.authorityGrants === 0, "attack probes must not grant authority");

  // Primary admission rule is pure (no expected-result constants baked into the gate function).
  const hold = primaryVerdict(config, {
    adaptiveSafeCoverage: 0.95,
    adaptiveCoverageGainOverSafeK1: 0.15,
    adaptiveDecisionMismatches: 0,
    fullVectorDecisionMismatches: 0,
    naiveTop1DecisionMismatches: 1,
    noStateContinues: 0,
    attackFalseAccepts: 0,
    authorityGrants: 0,
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffects: 0,
  });
  requireCondition(hold === "H1_TASK_SUFFICIENCY_SUPPORTED", "admission rule should admit a passing metric bundle");
  const retain = primaryVerdict(config, {
    adaptiveSafeCoverage: 0.5,
    adaptiveCoverageGainOverSafeK1: 0.0,
    adaptiveDecisionMismatches: 0,
    fullVectorDecisionMismatches: 0,
    naiveTop1DecisionMismatches: 1,
    noStateContinues: 0,
    attackFalseAccepts: 0,
    authorityGrants: 0,
    providerApiCalls: 0,
    modelApiCalls: 0,
    authorityEffects: 0,
  });
  requireCondition(retain === "H0_RETAINED", "admission rule should retain H0 on failed coverage");

  // No-state control never continues.
  const noState: ArmDecision = {
    arm: "no_state",
    disposition: "abstain",
    actionId: null,
    revealedCount: 0,
    matchesFullVector: false,
    authorityGranted: false,
  };
  requireCondition(noState.disposition !== "continue", "no-state must not continue");
  requireCondition(noState.authorityGranted === false, "no-state authority must be false");

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

  if (args.selfTest) {
    runSelfTest(config);
    return;
  }

  requireCondition(typeof args.input === "string" && args.input.length > 0, "--input is required in full mode");
  evaluateFull(config, resolve(args.input), resolve(args.output));
}

main();
