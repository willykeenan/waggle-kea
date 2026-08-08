#!/usr/bin/env node
/**
 * Zero-model, fail-closed verifier for certified task-sufficient prediction
 * handoffs (Waggle + Kea v0.3 decision-sufficiency).
 *
 * Independently regenerates policies and recomputes vector IDs, full-vector
 * actions, robust pairwise lower bounds, safe coverage, controls, primary
 * verdict, samples, effects, checksums, and artifact inventory.
 *
 * Does NOT import src/waggle/decision-certificate.ts or
 * src/kea/decision-certificate.ts. Does not generate or inspect scored
 * BANKING77 experiment outputs during --self-test.
 *
 * Usage:
 *   node scripts/verify-decision-sufficiency.mjs --self-test
 *   node scripts/verify-decision-sufficiency.mjs --results <dir>
 */

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = resolve(repoRoot, "benchmarks/decision-sufficiency/config.v1.json");

const DECISION_POLICY_SCHEMA = "waggle.decision-policy.v1";
const DECISION_CERTIFICATE_SCHEMA = "waggle.decision-certificate.v1";
const EVALUATION_SCHEMA = "waggle.decision-sufficiency.evaluation.v1";
const ENVIRONMENT_SCHEMA = "waggle.decision-sufficiency.environment.v1";
const POLICIES_SCHEMA = "waggle.decision-sufficiency.policies.v1";
const ATTACKS_SCHEMA = "waggle.decision-sufficiency.attacks.v1";
const VECTOR_SCHEMA = "waggle.decision-sufficiency.vector.v1";
const DECISION_ROW_SCHEMA = "waggle.decision-sufficiency.decision.v1";
const SAMPLE_SCHEMA = "waggle.decision-sufficiency.sample.v1";

const SYMBOLIC_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,159}$/;
const MAX_LABELS = 1_024;
const MAX_ACTIONS = 32;
const MAX_COST_UNITS = 1_000_000;

const REQUIRED_ARTIFACTS = [
  "attacks.json",
  "decisions.jsonl",
  "environment.json",
  "evaluation.json",
  "policies.json",
  "samples.jsonl",
  "vectors.jsonl",
];

// ---------------------------------------------------------------------------
// Fail-closed helpers
// ---------------------------------------------------------------------------

function fail(message) {
  throw new Error(`Decision-sufficiency verification failed: ${message}`);
}

function requireCondition(condition, message) {
  if (!condition) fail(message);
}

function requireInteger(value, path, minimum, maximum) {
  requireCondition(Number.isSafeInteger(value), `${path} must be a safe integer`);
  requireCondition(value >= minimum && value <= maximum, `${path} is outside range`);
}

// ---------------------------------------------------------------------------
// Canonical JSON / content addressing (independent of production modules)
// ---------------------------------------------------------------------------

function normalize(value, seen) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON rejects non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("canonical JSON rejects cycles");
    seen.add(value);
    const out = value.map((item) => normalize(item, seen));
    seen.delete(value);
    return out;
  }
  if (typeof value === "object") {
    const object = value;
    if (seen.has(object)) throw new Error("canonical JSON rejects cycles");
    seen.add(object);
    const out = {};
    for (const key of Object.keys(object).sort()) {
      const item = object[key];
      if (item === undefined) continue;
      if (typeof item === "function" || typeof item === "symbol" || typeof item === "bigint") {
        throw new Error(`canonical JSON rejects ${typeof item} at ${key}`);
      }
      out[key] = normalize(item, seen);
    }
    seen.delete(object);
    return out;
  }
  throw new Error(`canonical JSON rejects ${typeof value}`);
}

function canonicalJson(value) {
  return JSON.stringify(normalize(value, new Set()));
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function hashCanonical(value) {
  return sha256Hex(canonicalJson(value));
}

function contentId(prefix, value) {
  return `${prefix}_${hashCanonical(value).slice(0, 20)}`;
}

// ---------------------------------------------------------------------------
// Frozen config loader
// ---------------------------------------------------------------------------

function loadFrozenConfig() {
  requireCondition(existsSync(CONFIG_PATH), "missing frozen config.v1.json");
  const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  requireCondition(
    config.schemaVersion === "waggle.decision-sufficiency.config.v1",
    "config schemaVersion drifted"
  );
  requireCondition(
    config.status === "preregistered-prospective-secondary-analysis",
    "config status drifted"
  );
  requireCondition(config.probabilityScale === 1_000_000, "probabilityScale drifted");
  requireCondition(config.maxRevealedProbabilities === 8, "maxRevealedProbabilities drifted");
  requireCondition(
    Array.isArray(config.fixedSafeControls) &&
      canonicalJson(config.fixedSafeControls) === canonicalJson([1, 3]),
    "fixedSafeControls drifted"
  );
  requireCondition(
    config.policyFamily?.type === "sha256-partitioned-four-action-zero-one-cost",
    "policy family type drifted"
  );
  requireCondition(config.policyFamily.actionCount === 4, "policy actionCount drifted");
  requireCondition(config.policyFamily.matchCostUnits === 0, "matchCostUnits drifted");
  requireCondition(config.policyFamily.mismatchCostUnits === 1000, "mismatchCostUnits drifted");
  requireCondition(
    Array.isArray(config.policyFamily.seeds) && config.policyFamily.seeds.length === 12,
    "policy seed denominator drifted"
  );
  requireCondition(config.certificateSampleCases === 128, "certificateSampleCases drifted");
  requireCondition(config.effects?.providerApiCallsMaximum === 0, "provider API budget drifted");
  requireCondition(config.effects?.modelApiCallsMaximum === 0, "model API budget drifted");
  requireCondition(config.effects?.authorityEffectsMaximum === 0, "authority effect budget drifted");
  return config;
}

// ---------------------------------------------------------------------------
// Policy regeneration (SHA-256 partitioned four-action zero-one cost)
// ---------------------------------------------------------------------------

function actionIdsForCount(actionCount) {
  return Array.from({ length: actionCount }, (_, index) => `action_${index}`);
}

/**
 * Assign each label to exactly one action via SHA-256(seed:labelId) big-endian
 * first 4 bytes modulo actionCount. Cost 0 for the assigned action, mismatch
 * cost for every other action (action-major cost matrix).
 */
function buildPartitionedPolicy(seed, labelIds, family) {
  const actionIds = actionIdsForCount(family.actionCount);
  const assignment = labelIds.map((labelId) => {
    const digest = createHash("sha256").update(`${seed}:${labelId}`, "utf8").digest();
    return digest.readUInt32BE(0) % family.actionCount;
  });
  const occupied = new Set(assignment);
  requireCondition(
    occupied.size === family.actionCount,
    `policy seed ${seed} does not cover every action`
  );
  const costMatrix = actionIds.map((_, actionIndex) =>
    assignment.map((assigned) =>
      assigned === actionIndex ? family.matchCostUnits : family.mismatchCostUnits
    )
  );
  const body = {
    schemaVersion: DECISION_POLICY_SCHEMA,
    labelIds: [...labelIds],
    actionIds,
    costMatrix,
  };
  return {
    ...body,
    policyId: contentId("decisionpolicy", body),
  };
}

function regeneratePolicies(config, labelIds) {
  return config.policyFamily.seeds.map((seed) =>
    buildPartitionedPolicy(seed, labelIds, config.policyFamily)
  );
}

function assertDecisionPolicy(policy) {
  requireCondition(
    policy !== null && typeof policy === "object" && !Array.isArray(policy),
    "policy must be a plain object"
  );
  const expectedKeys = ["actionIds", "costMatrix", "labelIds", "policyId", "schemaVersion"];
  requireCondition(
    canonicalJson(Object.keys(policy).sort()) === canonicalJson(expectedKeys),
    "policy fields are not canonical"
  );
  requireCondition(policy.schemaVersion === DECISION_POLICY_SCHEMA, "policy schemaVersion is invalid");
  requireCondition(
    typeof policy.policyId === "string" && /^decisionpolicy_[a-f0-9]{20}$/.test(policy.policyId),
    "policyId is invalid"
  );
  requireCondition(
    Array.isArray(policy.labelIds) &&
      policy.labelIds.length >= 2 &&
      policy.labelIds.length <= MAX_LABELS,
    "labelIds length is invalid"
  );
  requireCondition(new Set(policy.labelIds).size === policy.labelIds.length, "labelIds must be unique");
  requireCondition(
    policy.labelIds.every((item) => typeof item === "string" && SYMBOLIC_ID.test(item)),
    "labelIds must be symbolic identifiers"
  );
  requireCondition(
    Array.isArray(policy.actionIds) &&
      policy.actionIds.length >= 2 &&
      policy.actionIds.length <= MAX_ACTIONS,
    "actionIds length is invalid"
  );
  requireCondition(new Set(policy.actionIds).size === policy.actionIds.length, "actionIds must be unique");
  requireCondition(
    policy.actionIds.every((item) => typeof item === "string" && SYMBOLIC_ID.test(item)),
    "actionIds must be symbolic identifiers"
  );
  requireCondition(
    Array.isArray(policy.costMatrix) && policy.costMatrix.length === policy.actionIds.length,
    "costMatrix action dimension is invalid"
  );
  policy.costMatrix.forEach((row, actionIndex) => {
    requireCondition(
      Array.isArray(row) && row.length === policy.labelIds.length,
      `costMatrix[${actionIndex}] label dimension is invalid`
    );
    row.forEach((cost, labelIndex) => {
      requireCondition(
        Number.isSafeInteger(cost) && cost >= 0 && cost <= MAX_COST_UNITS,
        `costMatrix[${actionIndex}][${labelIndex}] is invalid`
      );
    });
  });
  const expectedId = contentId("decisionpolicy", {
    schemaVersion: policy.schemaVersion,
    labelIds: policy.labelIds,
    actionIds: policy.actionIds,
    costMatrix: policy.costMatrix,
  });
  requireCondition(policy.policyId === expectedId, "policyId does not match policy content");
}

// ---------------------------------------------------------------------------
// Independent certificate / vector / reference-decision math
// ---------------------------------------------------------------------------

function validateProbabilityVector(probabilities, scale, labelCount) {
  requireInteger(scale, "probabilityScale", 1, 1_000_000_000);
  requireCondition(Array.isArray(probabilities), "probabilities must be an array");
  if (labelCount !== undefined) {
    requireCondition(probabilities.length === labelCount, "probability vector length mismatch");
  }
  requireCondition(
    probabilities.length >= 2 && probabilities.length <= MAX_LABELS,
    "probability vector length is invalid"
  );
  let sum = 0;
  probabilities.forEach((value, index) => {
    requireInteger(value, `probabilities[${index}]`, 0, scale);
    sum += value;
  });
  requireCondition(sum === scale, `probability vector must sum exactly to ${scale}`);
}

function decisionVectorId(probabilities, probabilityScale) {
  validateProbabilityVector(probabilities, probabilityScale);
  return contentId("decisionvector", { probabilityScale, probabilities });
}

function referenceDecision(probabilities, probabilityScale, policy) {
  assertDecisionPolicy(policy);
  validateProbabilityVector(probabilities, probabilityScale, policy.labelIds.length);
  const actionCostUnits = policy.costMatrix.map((costs) =>
    costs.reduce((sum, cost, labelIndex) => sum + cost * probabilities[labelIndex], 0)
  );
  const minimum = Math.min(...actionCostUnits);
  const winners = actionCostUnits
    .map((cost, index) => ({ cost, index }))
    .filter((item) => item.cost === minimum);
  return winners.length === 1
    ? { disposition: "continue", actionId: policy.actionIds[winners[0].index], actionCostUnits }
    : { disposition: "insufficient_confidence", actionId: null, actionCostUnits };
}

function certifiedAction(revealed, residualUnits, policy) {
  const revealedIndexes = new Set(revealed.map((item) => item.index));
  const omittedIndexes = policy.labelIds
    .map((_, index) => index)
    .filter((index) => !revealedIndexes.has(index));
  const candidates = [];

  policy.actionIds.forEach((actionId, candidateIndex) => {
    const bounds = [];
    let valid = true;
    policy.actionIds.forEach((opponentActionId, opponentIndex) => {
      if (candidateIndex === opponentIndex) return;
      const knownAdvantage = revealed.reduce(
        (sum, item) =>
          sum +
          item.probabilityUnits *
            (policy.costMatrix[opponentIndex][item.index] -
              policy.costMatrix[candidateIndex][item.index]),
        0
      );
      const omittedMinimumDifference = omittedIndexes.length
        ? Math.min(
            ...omittedIndexes.map(
              (labelIndex) =>
                policy.costMatrix[opponentIndex][labelIndex] -
                policy.costMatrix[candidateIndex][labelIndex]
            )
          )
        : 0;
      const lowerAdvantageUnits = knownAdvantage + residualUnits * omittedMinimumDifference;
      bounds.push({ opponentActionId, lowerAdvantageUnits });
      if (lowerAdvantageUnits <= 0) valid = false;
    });
    if (valid) candidates.push({ actionId, bounds });
  });

  requireCondition(candidates.length <= 1, "decision bounds certified more than one action");
  return candidates[0] ?? null;
}

function certificateBody(value) {
  return {
    schemaVersion: value.schemaVersion,
    caseId: value.caseId,
    policyId: value.policyId,
    vectorId: value.vectorId,
    probabilityScale: value.probabilityScale,
    sourceProbabilityCount: value.sourceProbabilityCount,
    maxRevealed: value.maxRevealed,
    revealed: value.revealed,
    residualUnits: value.residualUnits,
    disposition: value.disposition,
    actionId: value.actionId,
    pairwiseLowerAdvantages: value.pairwiseLowerAdvantages,
    authorityGranted: value.authorityGranted,
  };
}

function createDecisionCertificate(input) {
  assertDecisionPolicy(input.policy);
  requireCondition(SYMBOLIC_ID.test(input.caseId), "caseId must be a symbolic identifier");
  validateProbabilityVector(input.probabilities, input.probabilityScale, input.policy.labelIds.length);
  requireInteger(input.maxRevealed, "maxRevealed", 1, input.probabilities.length);

  const ranking = input.probabilities
    .map((probabilityUnits, index) => ({ index, probabilityUnits }))
    .sort((left, right) => right.probabilityUnits - left.probabilityUnits || left.index - right.index);
  let selected = ranking.slice(0, input.maxRevealed);
  let result = null;
  for (let count = 1; count <= input.maxRevealed; count += 1) {
    const candidate = ranking.slice(0, count);
    const residualUnits =
      input.probabilityScale - candidate.reduce((sum, item) => sum + item.probabilityUnits, 0);
    const certified = certifiedAction(candidate, residualUnits, input.policy);
    if (certified) {
      selected = candidate;
      result = certified;
      break;
    }
  }
  const residualUnits =
    input.probabilityScale - selected.reduce((sum, item) => sum + item.probabilityUnits, 0);
  const body = {
    schemaVersion: DECISION_CERTIFICATE_SCHEMA,
    caseId: input.caseId,
    policyId: input.policy.policyId,
    vectorId: decisionVectorId(input.probabilities, input.probabilityScale),
    probabilityScale: input.probabilityScale,
    sourceProbabilityCount: input.probabilities.length,
    maxRevealed: input.maxRevealed,
    revealed: selected,
    residualUnits,
    disposition: result ? "continue" : "insufficient_confidence",
    actionId: result?.actionId ?? null,
    pairwiseLowerAdvantages: result?.bounds ?? [],
    authorityGranted: false,
  };
  return { ...body, certificateId: contentId("decisioncert", body) };
}

function verifyDecisionCertificateMath(certificate, policy) {
  const errors = [];
  try {
    assertDecisionPolicy(policy);
    requireCondition(
      certificate !== null && typeof certificate === "object" && !Array.isArray(certificate),
      "certificate must be an object"
    );
    const expectedKeys = [
      "actionId",
      "authorityGranted",
      "caseId",
      "certificateId",
      "disposition",
      "maxRevealed",
      "pairwiseLowerAdvantages",
      "policyId",
      "probabilityScale",
      "residualUnits",
      "revealed",
      "schemaVersion",
      "sourceProbabilityCount",
      "vectorId",
    ];
    requireCondition(
      canonicalJson(Object.keys(certificate).sort()) === canonicalJson(expectedKeys),
      "certificate fields are not canonical"
    );
    requireCondition(
      certificate.schemaVersion === DECISION_CERTIFICATE_SCHEMA,
      "certificate schemaVersion is invalid"
    );
    requireCondition(
      /^decisioncert_[a-f0-9]{20}$/.test(certificate.certificateId),
      "certificateId is invalid"
    );
    requireCondition(SYMBOLIC_ID.test(certificate.caseId), "certificate caseId is invalid");
    requireCondition(certificate.policyId === policy.policyId, "certificate policyId mismatch");
    requireCondition(
      /^decisionvector_[a-f0-9]{20}$/.test(certificate.vectorId),
      "certificate vectorId is invalid"
    );
    requireInteger(certificate.probabilityScale, "certificate.probabilityScale", 1, 1_000_000_000);
    requireInteger(certificate.sourceProbabilityCount, "certificate.sourceProbabilityCount", 2, MAX_LABELS);
    requireCondition(
      certificate.sourceProbabilityCount === policy.labelIds.length,
      "certificate label count mismatch"
    );
    requireInteger(
      certificate.maxRevealed,
      "certificate.maxRevealed",
      1,
      certificate.sourceProbabilityCount
    );
    requireCondition(Array.isArray(certificate.revealed), "certificate revealed must be an array");
    requireCondition(
      certificate.revealed.length >= 1 && certificate.revealed.length <= certificate.maxRevealed,
      "certificate revealed length is invalid"
    );
    const indexes = new Set();
    certificate.revealed.forEach((item, rank) => {
      requireCondition(
        item !== null && typeof item === "object" && !Array.isArray(item),
        `certificate.revealed[${rank}] is invalid`
      );
      requireCondition(
        canonicalJson(Object.keys(item).sort()) === canonicalJson(["index", "probabilityUnits"]),
        `certificate.revealed[${rank}] fields are invalid`
      );
      requireInteger(
        item.index,
        `certificate.revealed[${rank}].index`,
        0,
        certificate.sourceProbabilityCount - 1
      );
      requireInteger(
        item.probabilityUnits,
        `certificate.revealed[${rank}].probabilityUnits`,
        0,
        certificate.probabilityScale
      );
      requireCondition(!indexes.has(item.index), "certificate revealed indexes must be unique");
      indexes.add(item.index);
      if (rank > 0) {
        const previous = certificate.revealed[rank - 1];
        requireCondition(
          previous.probabilityUnits > item.probabilityUnits ||
            (previous.probabilityUnits === item.probabilityUnits && previous.index < item.index),
          "certificate revealed entries are not canonically ranked"
        );
      }
    });
    const revealedSum = certificate.revealed.reduce((sum, item) => sum + item.probabilityUnits, 0);
    requireInteger(certificate.residualUnits, "certificate.residualUnits", 0, certificate.probabilityScale);
    requireCondition(
      revealedSum + certificate.residualUnits === certificate.probabilityScale,
      "certificate probability mass is inconsistent"
    );
    requireCondition(certificate.authorityGranted === false, "certificate cannot grant authority");
    const recomputed = certifiedAction(certificate.revealed, certificate.residualUnits, policy);
    const expectedDisposition = recomputed ? "continue" : "insufficient_confidence";
    requireCondition(
      certificate.disposition === expectedDisposition,
      "certificate disposition does not match bounds"
    );
    requireCondition(
      certificate.actionId === (recomputed?.actionId ?? null),
      "certificate action does not match bounds"
    );
    requireCondition(
      canonicalJson(certificate.pairwiseLowerAdvantages) ===
        canonicalJson(recomputed?.bounds ?? []),
      "certificate pairwise bounds do not match recomputation"
    );
    requireCondition(
      certificate.certificateId === contentId("decisioncert", certificateBody(certificate)),
      "certificateId does not match certificate content"
    );
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }
  return errors;
}

function naiveTop1Action(probabilities, policy) {
  validateProbabilityVector(probabilities, probabilities.reduce((a, b) => a + b, 0), policy.labelIds.length);
  let bestIndex = 0;
  for (let index = 1; index < probabilities.length; index += 1) {
    if (
      probabilities[index] > probabilities[bestIndex] ||
      (probabilities[index] === probabilities[bestIndex] && index < bestIndex)
    ) {
      bestIndex = index;
    }
  }
  // Map top label to its zero-cost action under the policy (if unique cost-0 action for that label).
  const costs = policy.costMatrix.map((row) => row[bestIndex]);
  const minCost = Math.min(...costs);
  const winners = costs
    .map((cost, actionIndex) => ({ cost, actionIndex }))
    .filter((item) => item.cost === minCost);
  if (winners.length !== 1) {
    return { disposition: "insufficient_confidence", actionId: null, topLabelIndex: bestIndex };
  }
  return {
    disposition: "continue",
    actionId: policy.actionIds[winners[0].actionIndex],
    topLabelIndex: bestIndex,
  };
}

// ---------------------------------------------------------------------------
// Primary admission recomputation
// ---------------------------------------------------------------------------

function recomputePrimaryVerdict(metrics, admission) {
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
// Artifact I/O and inventory
// ---------------------------------------------------------------------------

function parseJsonl(text, name) {
  const lines = text.split("\n").filter((line) => line.length > 0);
  return lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      fail(`${name} line ${index + 1} is not valid JSON`);
    }
  });
}

function readJson(dir, name) {
  const path = resolve(dir, name);
  requireCondition(existsSync(path), `missing ${name}`);
  requireCondition(!lstatSync(path).isSymbolicLink(), `${name} must not be a symlink`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function readText(dir, name) {
  const path = resolve(dir, name);
  requireCondition(existsSync(path), `missing ${name}`);
  requireCondition(!lstatSync(path).isSymbolicLink(), `${name} must not be a symlink`);
  return readFileSync(path, "utf8");
}

function assertNoSymlinks(dir) {
  for (const name of readdirSync(dir)) {
    const path = resolve(dir, name);
    requireCondition(!lstatSync(path).isSymbolicLink(), `symlink artifact is forbidden: ${name}`);
  }
}

function assertInventory(dir) {
  assertNoSymlinks(dir);
  const names = readdirSync(dir).sort();
  const expected = [...REQUIRED_ARTIFACTS, "SHA256SUMS"].sort();
  requireCondition(
    canonicalJson(names) === canonicalJson(expected),
    `artifact inventory drifted: observed ${names.join(",")} expected ${expected.join(",")}`
  );
}

function assertChecksums(dir) {
  const checksumPath = resolve(dir, "SHA256SUMS");
  const entries = readFileSync(checksumPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const match = /^([a-f0-9]{64})  ([A-Za-z0-9._-]+)$/.exec(line);
      requireCondition(match, `malformed checksum line: ${line}`);
      return { digest: match[1], name: match[2] };
    });
  requireCondition(
    entries.length === REQUIRED_ARTIFACTS.length,
    "checksum denominator drifted"
  );
  requireCondition(
    entries.map((entry) => entry.name).join("\n") === [...REQUIRED_ARTIFACTS].sort().join("\n"),
    "checksums do not cover exactly the required artifacts"
  );
  for (const entry of entries) {
    const path = resolve(dir, entry.name);
    requireCondition(!lstatSync(path).isSymbolicLink(), `${entry.name} must not be a symlink`);
    const digest = sha256Hex(readFileSync(path));
    requireCondition(digest === entry.digest, `${entry.name} digest mismatch`);
  }
}

function rejectHiddenText(value, path) {
  if (value === null || value === undefined) return;
  if (typeof value === "string") {
    requireCondition(
      !("text" === path.split(".").pop()),
      `hidden text field at ${path}`
    );
    // Source text must never appear under committed prediction-state fields.
    if (path.endsWith(".text") || path.endsWith(".sourceText") || path.endsWith(".utterance")) {
      fail(`hidden source text at ${path}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectHiddenText(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "text" || key === "sourceText" || key === "utterance") {
        fail(`hidden text field at ${path}.${key}`);
      }
      if (key === "textIncluded") {
        requireCondition(child === false, `textIncluded must be false at ${path}.textIncluded`);
      }
      rejectHiddenText(child, `${path}.${key}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Full scored-package verification
// ---------------------------------------------------------------------------

function verifyResultsDirectory(resultsDir, config) {
  const dir = resolve(resultsDir);
  requireCondition(existsSync(dir), `results directory missing: ${dir}`);
  requireCondition(lstatSync(dir).isDirectory(), `results path is not a directory: ${dir}`);

  assertInventory(dir);
  assertChecksums(dir);

  const environment = readJson(dir, "environment.json");
  const policiesArtifact = readJson(dir, "policies.json");
  const evaluation = readJson(dir, "evaluation.json");
  const attacks = readJson(dir, "attacks.json");
  const vectors = parseJsonl(readText(dir, "vectors.jsonl"), "vectors.jsonl");
  const decisions = parseJsonl(readText(dir, "decisions.jsonl"), "decisions.jsonl");
  const samples = parseJsonl(readText(dir, "samples.jsonl"), "samples.jsonl");

  for (const [name, value] of [
    ["environment.json", environment],
    ["policies.json", policiesArtifact],
    ["evaluation.json", evaluation],
    ["attacks.json", attacks],
  ]) {
    rejectHiddenText(value, name);
  }
  vectors.forEach((row, index) => rejectHiddenText(row, `vectors.jsonl[${index}]`));
  decisions.forEach((row, index) => rejectHiddenText(row, `decisions.jsonl[${index}]`));
  samples.forEach((row, index) => rejectHiddenText(row, `samples.jsonl[${index}]`));

  // Environment schema and zero-effect contract
  requireCondition(environment.schemaVersion === ENVIRONMENT_SCHEMA, "environment schema mismatch");
  requireCondition(
    environment.status === "preregistered-prospective-secondary-analysis",
    "environment status drifted"
  );
  requireCondition(environment.providerApiCalls === 0, "environment provider API calls must be zero");
  requireCondition(environment.modelApiCalls === 0, "environment model API calls must be zero");
  requireCondition(
    environment.authorityEffectsExecuted === 0,
    "environment authority effects must be zero"
  );
  requireCondition(
    environment.scoredPhaseNetworkCalls === 0 || environment.scoredPhaseNetworkCalls === undefined,
    "scored-phase network calls must be zero"
  );

  // Policies
  requireCondition(policiesArtifact.schemaVersion === POLICIES_SCHEMA, "policies schema mismatch");
  requireCondition(Array.isArray(policiesArtifact.policies), "policies.policies must be an array");
  requireCondition(
    policiesArtifact.policies.length === config.policyFamily.seeds.length,
    "policy denominator drifted"
  );
  requireCondition(
    Array.isArray(policiesArtifact.labelIds) && policiesArtifact.labelIds.length >= 2,
    "policies.labelIds invalid"
  );
  const regenerated = regeneratePolicies(config, policiesArtifact.labelIds);
  policiesArtifact.policies.forEach((policy, index) => {
    assertDecisionPolicy(policy);
    requireCondition(
      canonicalJson(policy) === canonicalJson(regenerated[index]),
      `policy[${index}] does not match regenerated SHA-256 partition`
    );
  });
  const policyById = new Map(policiesArtifact.policies.map((policy) => [policy.policyId, policy]));

  // Vectors: integer mass, content IDs, no text
  requireCondition(vectors.length >= 1, "vectors.jsonl is empty");
  const vectorByCase = new Map();
  for (const row of vectors) {
    requireCondition(row.schemaVersion === VECTOR_SCHEMA, "vector schema mismatch");
    requireCondition(typeof row.caseId === "string" && SYMBOLIC_ID.test(row.caseId), "vector caseId invalid");
    requireCondition(row.textIncluded === false, "vector textIncluded must be false");
    requireCondition(!("text" in row), "vector contains source text");
    requireCondition(
      Array.isArray(row.probabilities) && row.probabilities.length === policiesArtifact.labelIds.length,
      `vector ${row.caseId} length mismatch`
    );
    validateProbabilityVector(row.probabilities, config.probabilityScale, policiesArtifact.labelIds.length);
    const expectedVectorId = decisionVectorId(row.probabilities, config.probabilityScale);
    requireCondition(row.vectorId === expectedVectorId, `vectorId mismatch for ${row.caseId}`);
    requireCondition(row.probabilityScale === config.probabilityScale, "vector probabilityScale drifted");
    requireCondition(!vectorByCase.has(row.caseId), `duplicate vector caseId ${row.caseId}`);
    vectorByCase.set(row.caseId, row);
  }

  // Decisions: recompute full-vector, adaptive, fixed-k, naive, no-state
  requireCondition(decisions.length >= 1, "decisions.jsonl is empty");
  let fullVectorNonTied = 0;
  let adaptiveSafeContinues = 0;
  let safeK1Continues = 0;
  let safeK3Continues = 0;
  let adaptiveDecisionMismatches = 0;
  let fullVectorDecisionMismatches = 0;
  let naiveTop1DecisionMismatches = 0;
  let noStateContinues = 0;
  let authorityGrants = 0;

  for (const row of decisions) {
    requireCondition(row.schemaVersion === DECISION_ROW_SCHEMA, "decision row schema mismatch");
    requireCondition(vectorByCase.has(row.caseId), `decision references unknown case ${row.caseId}`);
    requireCondition(policyById.has(row.policyId), `decision references unknown policy ${row.policyId}`);
    const vector = vectorByCase.get(row.caseId);
    const policy = policyById.get(row.policyId);
    requireCondition(row.vectorId === vector.vectorId, `decision vectorId drift for ${row.caseId}`);
    requireCondition(row.authorityGranted === false, "decision row grants authority");

    const reference = referenceDecision(vector.probabilities, config.probabilityScale, policy);
    requireCondition(
      row.fullVector.disposition === reference.disposition &&
        row.fullVector.actionId === reference.actionId,
      `full-vector decision mismatch for ${row.caseId}/${row.policyId}`
    );
    // Artifact self-consistency for reconstruction mismatch counter (should stay 0 when above holds).
    if (
      row.fullVector.disposition !== reference.disposition ||
      row.fullVector.actionId !== reference.actionId
    ) {
      fullVectorDecisionMismatches += 1;
    }

    if (reference.disposition === "continue") fullVectorNonTied += 1;

    requireCondition(
      row.adaptive?.certificate?.authorityGranted === false,
      `adaptive certificate grants authority for ${row.caseId}/${row.policyId}`
    );
    const adaptive = createDecisionCertificate({
      caseId: row.caseId,
      probabilities: vector.probabilities,
      probabilityScale: config.probabilityScale,
      policy,
      maxRevealed: config.maxRevealedProbabilities,
    });
    const adaptiveErrors = verifyDecisionCertificateMath(adaptive, policy);
    requireCondition(adaptiveErrors.length === 0, `adaptive certificate math failed: ${adaptiveErrors[0]}`);
    const storedAdaptiveErrors = verifyDecisionCertificateMath(row.adaptive.certificate, policy);
    requireCondition(
      storedAdaptiveErrors.length === 0,
      `stored adaptive certificate invalid for ${row.caseId}/${row.policyId}: ${storedAdaptiveErrors[0]}`
    );
    requireCondition(
      canonicalJson(row.adaptive.certificate) === canonicalJson(adaptive),
      `adaptive certificate drift for ${row.caseId}/${row.policyId}`
    );
    if (adaptive.authorityGranted !== false) authorityGrants += 1;
    if (adaptive.disposition === "continue") {
      adaptiveSafeContinues += 1;
      if (reference.disposition !== "continue" || adaptive.actionId !== reference.actionId) {
        adaptiveDecisionMismatches += 1;
      }
    }

    for (const k of config.fixedSafeControls) {
      const fixed = createDecisionCertificate({
        caseId: row.caseId,
        probabilities: vector.probabilities,
        probabilityScale: config.probabilityScale,
        policy,
        maxRevealed: k,
      });
      requireCondition(
        canonicalJson(row[`safeK${k}`].certificate) === canonicalJson(fixed),
        `safe k=${k} certificate drift for ${row.caseId}/${row.policyId}`
      );
      if (fixed.disposition === "continue") {
        if (k === 1) safeK1Continues += 1;
        if (k === 3) safeK3Continues += 1;
      }
    }

    const naive = naiveTop1Action(vector.probabilities, policy);
    requireCondition(
      row.naiveTop1.disposition === naive.disposition && row.naiveTop1.actionId === naive.actionId,
      `naive top-1 drift for ${row.caseId}/${row.policyId}`
    );
    if (
      reference.disposition === "continue" &&
      (naive.disposition !== "continue" || naive.actionId !== reference.actionId)
    ) {
      naiveTop1DecisionMismatches += 1;
    }

    requireCondition(
      row.noState.disposition === "insufficient_confidence" || row.noState.disposition === "abstain",
      `no-state must abstain for ${row.caseId}/${row.policyId}`
    );
    requireCondition(row.noState.actionId === null, "no-state must not emit an action");
    if (row.noState.disposition === "continue") noStateContinues += 1;

    // Kea qualification / restricted consumer claims on the row must never grant authority.
    if (row.qualification) {
      requireCondition(row.qualification.authorityGranted === false, "qualification grants authority");
      requireCondition(
        row.qualification.disposition === "qualified" ||
          row.qualification.disposition === "abstained" ||
          row.qualification.disposition === "rejected",
        "qualification disposition invalid"
      );
    }
    if (row.restricted) {
      requireCondition(row.restricted.authorityGranted === false, "restricted consumer grants authority");
    }
  }

  const adaptiveSafeCoverage =
    fullVectorNonTied === 0 ? 0 : adaptiveSafeContinues / fullVectorNonTied;
  const safeK1Coverage = fullVectorNonTied === 0 ? 0 : safeK1Continues / fullVectorNonTied;
  const safeK3Coverage = fullVectorNonTied === 0 ? 0 : safeK3Continues / fullVectorNonTied;

  // Evaluation aggregate + primary verdict
  requireCondition(evaluation.schemaVersion === EVALUATION_SCHEMA, "evaluation schema mismatch");
  requireCondition(
    evaluation.status === "preregistered-prospective-secondary-analysis",
    "evaluation status drifted"
  );
  requireCondition(evaluation.authorityGranted === false, "evaluation grants authority");
  requireCondition(evaluation.caseCount === vectorByCase.size, "evaluation caseCount drifted");
  requireCondition(
    evaluation.decisionCount === decisions.length,
    "evaluation decisionCount drifted"
  );
  requireCondition(
    Math.abs(evaluation.metrics.adaptiveSafeCoverage - adaptiveSafeCoverage) < 1e-12,
    "adaptiveSafeCoverage mismatch"
  );
  requireCondition(
    Math.abs(evaluation.metrics.safeK1Coverage - safeK1Coverage) < 1e-12,
    "safeK1Coverage mismatch"
  );
  requireCondition(
    Math.abs(evaluation.metrics.safeK3Coverage - safeK3Coverage) < 1e-12,
    "safeK3Coverage mismatch"
  );
  requireCondition(
    evaluation.metrics.adaptiveDecisionMismatches === adaptiveDecisionMismatches,
    "adaptiveDecisionMismatches mismatch"
  );
  requireCondition(
    evaluation.metrics.fullVectorDecisionMismatches === fullVectorDecisionMismatches,
    "fullVectorDecisionMismatches mismatch"
  );
  requireCondition(
    evaluation.metrics.naiveTop1DecisionMismatches === naiveTop1DecisionMismatches,
    "naiveTop1DecisionMismatches mismatch"
  );
  requireCondition(
    evaluation.metrics.noStateContinues === noStateContinues,
    "noStateContinues mismatch"
  );

  // Effects
  requireCondition(evaluation.effects.providerApiCalls === 0, "evaluation provider API calls nonzero");
  requireCondition(evaluation.effects.modelApiCalls === 0, "evaluation model API calls nonzero");
  requireCondition(
    evaluation.effects.authorityEffectsExecuted === 0,
    "evaluation authority effects nonzero"
  );
  requireCondition(
    evaluation.effects.providerApiCalls === environment.providerApiCalls,
    "provider API call counts disagree"
  );
  requireCondition(
    evaluation.effects.modelApiCalls === environment.modelApiCalls,
    "model API call counts disagree"
  );

  // Attacks
  requireCondition(attacks.schemaVersion === ATTACKS_SCHEMA, "attacks schema mismatch");
  requireCondition(attacks.authorityGranted === false, "attacks artifact grants authority");
  requireCondition(attacks.allSpecifiedTampersRejected === true, "attack suite did not fully reject");
  requireCondition(attacks.falseAccepts === 0, "attack suite false accepts recorded");
  requireCondition(Array.isArray(attacks.cases) && attacks.cases.length >= 1, "attacks.cases empty");
  for (const attack of attacks.cases) {
    requireCondition(attack.rejected === true, `attack ${attack.name} was not rejected`);
    requireCondition(attack.authorityGranted === false, `attack ${attack.name} granted authority`);
  }

  // Samples (text-free certificate samples)
  requireCondition(
    samples.length === config.certificateSampleCases || samples.length === evaluation.sampleCount,
    "sample denominator drifted"
  );
  requireCondition(
    evaluation.sampleCount === samples.length,
    "evaluation.sampleCount disagrees with samples.jsonl"
  );
  for (const sample of samples) {
    requireCondition(sample.schemaVersion === SAMPLE_SCHEMA, "sample schema mismatch");
    requireCondition(sample.textIncluded === false, "sample textIncluded must be false");
    requireCondition(!("text" in sample), "sample contains source text");
    requireCondition(vectorByCase.has(sample.caseId), `sample unknown case ${sample.caseId}`);
    requireCondition(policyById.has(sample.policyId), `sample unknown policy ${sample.policyId}`);
    const vector = vectorByCase.get(sample.caseId);
    const policy = policyById.get(sample.policyId);
    const expected = createDecisionCertificate({
      caseId: sample.caseId,
      probabilities: vector.probabilities,
      probabilityScale: config.probabilityScale,
      policy,
      maxRevealed: config.maxRevealedProbabilities,
    });
    requireCondition(
      canonicalJson(sample.certificate) === canonicalJson(expected),
      `sample certificate drift for ${sample.caseId}/${sample.policyId}`
    );
    requireCondition(sample.certificate.authorityGranted === false, "sample certificate grants authority");
    const mathErrors = verifyDecisionCertificateMath(sample.certificate, policy);
    requireCondition(mathErrors.length === 0, `sample certificate math failed: ${mathErrors[0]}`);
  }

  const primary = recomputePrimaryVerdict(
    {
      adaptiveSafeCoverage,
      safeK1Coverage,
      adaptiveDecisionMismatches,
      fullVectorDecisionMismatches,
      naiveTop1DecisionMismatches,
      noStateContinues,
      attacksRejected: attacks.allSpecifiedTampersRejected === true && attacks.falseAccepts === 0,
      authorityGrants:
        authorityGrants +
        (evaluation.authorityGranted === false && attacks.authorityGranted === false ? 0 : 1),
      providerApiCalls: evaluation.effects.providerApiCalls,
      modelApiCalls: evaluation.effects.modelApiCalls,
      authorityEffects: evaluation.effects.authorityEffectsExecuted,
    },
    config.primaryAdmission
  );

  requireCondition(
    evaluation.scientificVerdict === primary.scientificVerdict,
    `scientificVerdict mismatch: artifact ${evaluation.scientificVerdict} recomputed ${primary.scientificVerdict}`
  );
  requireCondition(
    canonicalJson(evaluation.primaryGates) === canonicalJson(primary.gates),
    "primaryGates mismatch"
  );

  return {
    ok: true,
    scientificVerdict: primary.scientificVerdict,
    cases: vectorByCase.size,
    decisions: decisions.length,
    adaptiveSafeCoverage,
    safeK1Coverage,
    adaptiveDecisionMismatches,
    naiveTop1DecisionMismatches,
    noStateContinues,
    authorityGrants: 0,
    effects: evaluation.effects,
  };
}

// ---------------------------------------------------------------------------
// Synthetic self-test (no scored outputs, no production imports)
// ---------------------------------------------------------------------------

function fixturePolicy() {
  const body = {
    schemaVersion: DECISION_POLICY_SCHEMA,
    labelIds: ["label_a", "label_b", "label_c", "label_d"],
    actionIds: ["queue_left", "queue_right"],
    costMatrix: [
      [0, 0, 1_000, 1_000],
      [1_000, 1_000, 0, 0],
    ],
  };
  return { ...body, policyId: contentId("decisionpolicy", body) };
}

function writeSha256Sums(dir, names) {
  const lines = [...names]
    .sort()
    .map((name) => `${sha256Hex(readFileSync(join(dir, name)))}  ${name}`);
  writeFileSync(join(dir, "SHA256SUMS"), `${lines.join("\n")}\n`, "utf8");
}


/**
 * Build a valid seed-partitioned synthetic results directory that full mode accepts.
 */
function materializeValidResults(dir, tamper = {}) {
  const config = loadFrozenConfig();
  // 16 synthetic labels keep four-action SHA-256 partitions fully occupied
  // for every frozen policy seed without using scored BANKING77 outputs.
  const syntheticLabels = Array.from({ length: 16 }, (_, i) => `label_${i}`);
  const policies = regeneratePolicies(config, syntheticLabels);
  // If any seed failed, regeneratePolicies already threw.

  const scale = config.probabilityScale;
  // Construct vectors: one decisive, one tied-ish, one naive-mismatch oriented.
  function massOn(indexes, weights) {
    const probabilities = Array(syntheticLabels.length).fill(0);
    let remaining = scale;
    indexes.forEach((labelIndex, i) => {
      const value = i === indexes.length - 1 ? remaining : weights[i];
      probabilities[labelIndex] = value;
      remaining -= value;
    });
    return probabilities;
  }

  const cases = [
    {
      caseId: "case_constructive",
      probabilities: massOn([0, 1, 2, 3], [700_000, 100_000, 100_000, 100_000]),
    },
    {
      caseId: "case_spread",
      probabilities: massOn(
        [0, 1, 2, 3, 4, 5, 6, 7],
        [200_000, 150_000, 150_000, 100_000, 100_000, 100_000, 100_000, 100_000]
      ),
    },
    {
      caseId: "case_alt",
      probabilities: massOn([4, 5, 6, 7], [400_000, 300_000, 200_000, 100_000]),
    },
  ];

  // Ensure integer sum
  for (const item of cases) {
    const sum = item.probabilities.reduce((a, b) => a + b, 0);
    requireCondition(sum === scale, "synthetic vector sum construction failed");
  }

  // Build certificates against valid mass first; apply mass/id tampers on the
  // emitted vector rows afterward so construction does not throw.
  const vectors = cases.map((item) => ({
    schemaVersion: VECTOR_SCHEMA,
    caseId: item.caseId,
    vectorId: decisionVectorId(item.probabilities, scale),
    probabilityScale: scale,
    probabilities: [...item.probabilities],
    textIncluded: false,
  }));

  const policy = policies[0];
  const decisions = [];
  for (const vector of vectors) {
    let reference;
    try {
      reference = referenceDecision(vector.probabilities, scale, policy);
    } catch {
      reference = { disposition: "insufficient_confidence", actionId: null };
    }

    let adaptive;
    try {
      adaptive = createDecisionCertificate({
        caseId: vector.caseId,
        probabilities: vector.probabilities,
        probabilityScale: scale,
        policy,
        maxRevealed: config.maxRevealedProbabilities,
      });
    } catch {
      adaptive = {
        schemaVersion: DECISION_CERTIFICATE_SCHEMA,
        caseId: vector.caseId,
        policyId: policy.policyId,
        vectorId: vector.vectorId,
        probabilityScale: scale,
        sourceProbabilityCount: syntheticLabels.length,
        maxRevealed: config.maxRevealedProbabilities,
        revealed: [{ index: 0, probabilityUnits: vector.probabilities[0] }],
        residualUnits: scale - vector.probabilities[0],
        disposition: "insufficient_confidence",
        actionId: null,
        pairwiseLowerAdvantages: [],
        authorityGranted: false,
        certificateId: "decisioncert_" + "0".repeat(20),
      };
    }

    if (tamper.forgedBounds && adaptive.pairwiseLowerAdvantages?.length) {
      adaptive = structuredClone(adaptive);
      adaptive.pairwiseLowerAdvantages[0].lowerAdvantageUnits += 1;
      adaptive.certificateId = contentId("decisioncert", certificateBody(adaptive));
    }
    if (tamper.forgedAction) {
      adaptive = structuredClone(adaptive);
      adaptive.actionId = policy.actionIds[0];
      adaptive.disposition = "continue";
      adaptive.certificateId = contentId("decisioncert", certificateBody(adaptive));
    }
    if (tamper.authoritySmuggle) {
      adaptive = structuredClone(adaptive);
      adaptive.authorityGranted = true;
      adaptive.certificateId = contentId("decisioncert", certificateBody(adaptive));
    }

    const safeK1 = createDecisionCertificate({
      caseId: vector.caseId,
      probabilities: vector.probabilities,
      probabilityScale: scale,
      policy,
      maxRevealed: 1,
    });
    const safeK3 = createDecisionCertificate({
      caseId: vector.caseId,
      probabilities: vector.probabilities,
      probabilityScale: scale,
      policy,
      maxRevealed: 3,
    });
    const naive = naiveTop1Action(vector.probabilities, policy);

    decisions.push({
      schemaVersion: DECISION_ROW_SCHEMA,
      caseId: vector.caseId,
      policyId: policy.policyId,
      vectorId: vector.vectorId,
      authorityGranted: false,
      fullVector: {
        disposition: reference.disposition,
        actionId: reference.actionId,
      },
      adaptive: { certificate: adaptive },
      safeK1: { certificate: safeK1 },
      safeK3: { certificate: safeK3 },
      naiveTop1: { disposition: naive.disposition, actionId: naive.actionId },
      noState: { disposition: "abstain", actionId: null },
      qualification: {
        disposition:
          adaptive.disposition === "continue"
            ? "qualified"
            : adaptive.disposition === "insufficient_confidence"
              ? "abstained"
              : "rejected",
        authorityGranted: false,
      },
      restricted: {
        disposition:
          adaptive.disposition === "continue" ? "continue" : "insufficient_confidence",
        actionId: adaptive.disposition === "continue" ? adaptive.actionId : null,
        authorityGranted: false,
      },
    });
  }

  // Optionally produce more decisions across policies so primary metrics are coherent.
  // Full mode iterates all decision rows; metrics use all of them.
  // For self-test include only policy[0] rows to keep package small.

  let fullVectorNonTied = 0;
  let adaptiveSafeContinues = 0;
  let safeK1Continues = 0;
  let safeK3Continues = 0;
  let adaptiveDecisionMismatches = 0;
  let fullVectorDecisionMismatches = 0;
  let naiveTop1DecisionMismatches = 0;
  let noStateContinues = 0;

  for (const row of decisions) {
    const vector = vectors.find((v) => v.caseId === row.caseId);
    try {
      const reference = referenceDecision(vector.probabilities, scale, policy);
      if (reference.disposition === "continue") fullVectorNonTied += 1;
      if (row.adaptive.certificate.disposition === "continue") {
        adaptiveSafeContinues += 1;
        if (reference.disposition !== "continue" || row.adaptive.certificate.actionId !== reference.actionId) {
          adaptiveDecisionMismatches += 1;
        }
      }
      if (row.safeK1.certificate.disposition === "continue") safeK1Continues += 1;
      if (row.safeK3.certificate.disposition === "continue") safeK3Continues += 1;
      const naive = naiveTop1Action(vector.probabilities, policy);
      if (
        reference.disposition === "continue" &&
        (naive.disposition !== "continue" || naive.actionId !== reference.actionId)
      ) {
        naiveTop1DecisionMismatches += 1;
      }
      if (row.noState.disposition === "continue") noStateContinues += 1;
    } catch {
      /* invalid mass */
    }
  }

  const adaptiveSafeCoverage =
    fullVectorNonTied === 0 ? 0 : adaptiveSafeContinues / fullVectorNonTied;
  const safeK1Coverage = fullVectorNonTied === 0 ? 0 : safeK1Continues / fullVectorNonTied;
  const safeK3Coverage = fullVectorNonTied === 0 ? 0 : safeK3Continues / fullVectorNonTied;

  const metrics = {
    adaptiveSafeCoverage: tamper.driftCoverage ? 0.99 : adaptiveSafeCoverage,
    safeK1Coverage,
    safeK3Coverage,
    adaptiveDecisionMismatches,
    fullVectorDecisionMismatches,
    naiveTop1DecisionMismatches,
    noStateContinues,
  };

  const primary = recomputePrimaryVerdict(
    {
      ...metrics,
      attacksRejected: !tamper.attackAccept,
      authorityGrants: 0,
      providerApiCalls: tamper.nonzeroEffects ? 1 : 0,
      modelApiCalls: 0,
      authorityEffects: 0,
    },
    config.primaryAdmission
  );

  // Sample count: evaluation.sampleCount must equal samples.jsonl length.
  // Full mode allows samples.length === config.certificateSampleCases OR evaluation.sampleCount.
  const samples = decisions.map((row) => ({
    schemaVersion: SAMPLE_SCHEMA,
    caseId: row.caseId,
    policyId: row.policyId,
    textIncluded: false,
    certificate: row.adaptive.certificate,
  }));

  const environment = {
    schemaVersion: ENVIRONMENT_SCHEMA,
    status: "preregistered-prospective-secondary-analysis",
    providerApiCalls: tamper.nonzeroEffects ? 1 : 0,
    modelApiCalls: 0,
    authorityEffectsExecuted: 0,
    scoredPhaseNetworkCalls: 0,
  };

  let policiesArtifact = {
    schemaVersion: POLICIES_SCHEMA,
    labelIds: syntheticLabels,
    policies: structuredClone(policies),
  };
  if (tamper.policyDrift) {
    policiesArtifact = structuredClone(policiesArtifact);
    policiesArtifact.policies[0].costMatrix[0][0] =
      policiesArtifact.policies[0].costMatrix[0][0] === 0 ? 1 : 0;
    // leave policyId stale → fail content match / regenerate mismatch
  }

  const evaluation = {
    schemaVersion: EVALUATION_SCHEMA,
    status: "preregistered-prospective-secondary-analysis",
    authorityGranted: tamper.evaluationAuthority ? true : false,
    caseCount: vectors.length,
    decisionCount: decisions.length,
    sampleCount: samples.length,
    metrics,
    primaryGates: primary.gates,
    scientificVerdict: primary.scientificVerdict,
    effects: {
      providerApiCalls: tamper.nonzeroEffects ? 1 : 0,
      modelApiCalls: 0,
      authorityEffectsExecuted: 0,
    },
  };

  const attacks = {
    schemaVersion: ATTACKS_SCHEMA,
    authorityGranted: false,
    allSpecifiedTampersRejected: tamper.attackAccept ? false : true,
    falseAccepts: tamper.attackAccept ? 1 : 0,
    cases: [
      {
        name: "forged_bounds",
        rejected: tamper.attackAccept ? false : true,
        authorityGranted: false,
      },
      {
        name: "forged_vector_id",
        rejected: true,
        authorityGranted: false,
      },
      {
        name: "authority_smuggle",
        rejected: true,
        authorityGranted: false,
      },
    ],
  };

  // Post-construction tampers on emitted vectors (keep decision rows coherent).
  if (tamper.badMass) {
    vectors[0].probabilities[0] -= 1;
  }
  if (tamper.forgedVectorId) {
    for (const vector of vectors) {
      vector.vectorId = `decisionvector_${"0".repeat(20)}`;
    }
  }
  if (tamper.hiddenText) {
    for (const vector of vectors) {
      vector.textIncluded = true;
      vector.text = "hidden utterance";
    }
  }

  if (tamper.extraArtifact) {
    writeFileSync(join(dir, "notes.txt"), "extra\n", "utf8");
  }

  writeFileSync(join(dir, "environment.json"), `${canonicalJson(environment)}\n`, "utf8");
  writeFileSync(join(dir, "policies.json"), `${canonicalJson(policiesArtifact)}\n`, "utf8");
  writeFileSync(join(dir, "evaluation.json"), `${canonicalJson(evaluation)}\n`, "utf8");
  writeFileSync(join(dir, "attacks.json"), `${canonicalJson(attacks)}\n`, "utf8");
  writeFileSync(
    join(dir, "vectors.jsonl"),
    `${vectors.map((row) => JSON.stringify(row)).join("\n")}\n`,
    "utf8"
  );
  writeFileSync(
    join(dir, "decisions.jsonl"),
    `${decisions.map((row) => JSON.stringify(row)).join("\n")}\n`,
    "utf8"
  );
  writeFileSync(
    join(dir, "samples.jsonl"),
    `${samples.map((row) => JSON.stringify(row)).join("\n")}\n`,
    "utf8"
  );

  if (!tamper.missingChecksums) {
    const names = [...REQUIRED_ARTIFACTS];
    if (tamper.extraArtifact) {
      // inventory will fail before or after checksums
    }
    if (tamper.badChecksum) {
      const lines = [...REQUIRED_ARTIFACTS]
        .sort()
        .map((name) => {
          const digest =
            name === "environment.json"
              ? "0".repeat(64)
              : sha256Hex(readFileSync(join(dir, name)));
          return `${digest}  ${name}`;
        });
      writeFileSync(join(dir, "SHA256SUMS"), `${lines.join("\n")}\n`, "utf8");
    } else {
      writeSha256Sums(dir, REQUIRED_ARTIFACTS);
    }
  }

  if (tamper.missingArtifact) {
    rmSync(join(dir, "samples.jsonl"), { force: true });
  }

  return { config, policies, vectors, decisions };
}

function expectFailure(fn, pattern) {
  let failed = false;
  let message = "";
  try {
    fn();
  } catch (error) {
    failed = true;
    message = error instanceof Error ? error.message : String(error);
  }
  requireCondition(failed, `expected failure matching ${pattern} but succeeded`);
  requireCondition(
    pattern.test(message),
    `expected failure matching ${pattern}, got: ${message}`
  );
}

function runSelfTest() {
  // This verifier is intentionally self-contained: it never imports
  // src/waggle/decision-certificate.ts or src/kea/decision-certificate.ts.

  // --- Pure math: constructive certificate ---
  const policy = fixturePolicy();
  const constructive = [700_000, 100_000, 100_000, 100_000];
  const ref = referenceDecision(constructive, 1_000_000, policy);
  requireCondition(ref.disposition === "continue" && ref.actionId === "queue_left", "constructive full-vector");
  const cert = createDecisionCertificate({
    caseId: "case_constructive",
    probabilities: constructive,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });
  requireCondition(cert.disposition === "continue", "constructive certificate disposition");
  requireCondition(cert.actionId === "queue_left", "constructive certificate action");
  requireCondition(cert.revealed.length === 1, "constructive should certify at k=1");
  requireCondition(cert.residualUnits === 300_000, "constructive residual");
  requireCondition(cert.authorityGranted === false, "constructive authority");
  requireCondition(verifyDecisionCertificateMath(cert, policy).length === 0, "constructive math");

  // --- Progressive reveal ---
  const progressive = [400_000, 300_000, 200_000, 100_000];
  const progCert = createDecisionCertificate({
    caseId: "case_progressive",
    probabilities: progressive,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 2,
  });
  requireCondition(progCert.disposition === "continue", "progressive disposition");
  requireCondition(progCert.revealed.length === 2, "progressive reveal count");

  // --- Insufficient confidence ---
  const tied = [300_000, 200_000, 300_000, 200_000];
  const tiedRef = referenceDecision(tied, 1_000_000, policy);
  requireCondition(tiedRef.disposition === "insufficient_confidence", "tied full-vector");
  const tiedCert = createDecisionCertificate({
    caseId: "case_tied",
    probabilities: tied,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });
  requireCondition(tiedCert.disposition === "insufficient_confidence", "tied certificate");
  requireCondition(tiedCert.actionId === null, "tied action null");

  // --- Vector identity ---
  const vid = decisionVectorId(constructive, 1_000_000);
  requireCondition(/^decisionvector_[a-f0-9]{20}$/.test(vid), "vector id format");
  requireCondition(vid === decisionVectorId(constructive, 1_000_000), "vector id stable");

  // --- Non-integer / bad mass rejection ---
  expectFailure(
    () => validateProbabilityVector([700_000, 100_000, 100_000, 99_999], 1_000_000),
    /sum exactly/
  );
  expectFailure(
    () => validateProbabilityVector([700_000.5, 100_000, 100_000, 99_999.5], 1_000_000),
    /safe integer/
  );
  expectFailure(
    () => validateProbabilityVector([-1, 500_001, 250_000, 250_000], 1_000_000),
    /outside range/
  );

  // --- Forged bounds / action / certificateId ---
  const badBounds = structuredClone(cert);
  badBounds.pairwiseLowerAdvantages[0].lowerAdvantageUnits += 1;
  requireCondition(
    verifyDecisionCertificateMath(badBounds, policy).some((e) => /pairwise bounds|certificateId/.test(e)),
    "forged bounds must fail"
  );

  const badAction = structuredClone(cert);
  badAction.actionId = "queue_right";
  requireCondition(verifyDecisionCertificateMath(badAction, policy).length > 0, "forged action must fail");

  const badId = structuredClone(cert);
  badId.certificateId = `decisioncert_${"0".repeat(20)}`;
  requireCondition(
    verifyDecisionCertificateMath(badId, policy).some((e) => /certificateId/.test(e)),
    "forged certificateId must fail"
  );

  const authority = structuredClone(cert);
  authority.authorityGranted = true;
  requireCondition(
    verifyDecisionCertificateMath(authority, policy).some((e) => /authority/.test(e)),
    "authority smuggle must fail"
  );

  // --- Schema drift on certificate ---
  const extraField = { ...cert, note: "x" };
  requireCondition(
    verifyDecisionCertificateMath(extraField, policy).some((e) => /canonical|fields/.test(e)),
    "extra certificate field must fail"
  );

  // --- Policy regeneration determinism ---
  const config = loadFrozenConfig();
  const labels = Array.from({ length: 16 }, (_, i) => `label_${i}`);
  const policiesA = regeneratePolicies(config, labels);
  const policiesB = regeneratePolicies(config, labels);
  requireCondition(policiesA.length === 12, "12 policies required");
  requireCondition(
    canonicalJson(policiesA) === canonicalJson(policiesB),
    "policy regeneration must be deterministic"
  );
  for (const p of policiesA) {
    assertDecisionPolicy(p);
    requireCondition(p.actionIds.length === 4, "four actions");
  }

  // --- Full package valid path ---
  const validDir = mkdtempSync(join(tmpdir(), "decision-sufficiency-valid-"));
  try {
    materializeValidResults(validDir);
    const summary = verifyResultsDirectory(validDir, config);
    requireCondition(summary.ok === true, "valid package must pass");
    requireCondition(summary.authorityGrants === 0, "valid package authority");
    requireCondition(summary.effects.providerApiCalls === 0, "valid package effects");
  } finally {
    rmSync(validDir, { recursive: true, force: true });
  }

  // --- Tampered packages fail closed ---
  const tampers = [
    { name: "badMass", tamper: { badMass: true }, pattern: /sum exactly|probability/ },
    { name: "forgedVectorId", tamper: { forgedVectorId: true }, pattern: /vectorId/ },
    { name: "forgedBounds", tamper: { forgedBounds: true }, pattern: /certificate|bounds|drift/ },
    { name: "forgedAction", tamper: { forgedAction: true }, pattern: /certificate|action|drift|bounds|disposition/ },
    { name: "authoritySmuggle", tamper: { authoritySmuggle: true }, pattern: /authority/ },
    { name: "hiddenText", tamper: { hiddenText: true }, pattern: /text/ },
    { name: "policyDrift", tamper: { policyDrift: true }, pattern: /policy/ },
    { name: "driftCoverage", tamper: { driftCoverage: true }, pattern: /Coverage|coverage|primaryGates|scientificVerdict/ },
    { name: "nonzeroEffects", tamper: { nonzeroEffects: true }, pattern: /API|effect|provider/i },
    { name: "attackAccept", tamper: { attackAccept: true }, pattern: /attack|primaryGates|scientificVerdict|false accept/i },
    { name: "extraArtifact", tamper: { extraArtifact: true }, pattern: /inventory/ },
    { name: "missingArtifact", tamper: { missingArtifact: true }, pattern: /missing|inventory/ },
    { name: "badChecksum", tamper: { badChecksum: true }, pattern: /digest/ },
    { name: "evaluationAuthority", tamper: { evaluationAuthority: true }, pattern: /authority/ },
  ];

  for (const { name, tamper, pattern } of tampers) {
    const dir = mkdtempSync(join(tmpdir(), `decision-sufficiency-${name}-`));
    try {
      materializeValidResults(dir, tamper);
      expectFailure(() => verifyResultsDirectory(dir, config), pattern);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  console.log("VERIFIER_SELF_TEST_OK");
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function main(argv) {
  if (argv.includes("--self-test")) {
    runSelfTest();
    return;
  }

  const resultsFlag = argv.indexOf("--results");
  if (resultsFlag < 0 || !argv[resultsFlag + 1]) {
    process.stderr.write(
      "Usage:\n" +
        "  node scripts/verify-decision-sufficiency.mjs --self-test\n" +
        "  node scripts/verify-decision-sufficiency.mjs --results <dir>\n"
    );
    process.exit(2);
  }

  const config = loadFrozenConfig();
  const summary = verifyResultsDirectory(argv[resultsFlag + 1], config);
  console.log(JSON.stringify(summary));
}

try {
  main(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
