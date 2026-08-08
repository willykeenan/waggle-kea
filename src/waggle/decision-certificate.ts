import { canonicalJson, contentId, hashCanonical } from "../kea/canonical.js";

export const DECISION_POLICY_SCHEMA = "waggle.decision-policy.v1" as const;
export const DECISION_CERTIFICATE_SCHEMA = "waggle.decision-certificate.v1" as const;

export interface WaggleDecisionPolicy {
  schemaVersion: typeof DECISION_POLICY_SCHEMA;
  policyId: string;
  labelIds: string[];
  actionIds: string[];
  /** Action-major integer cost matrix: costMatrix[action][label]. */
  costMatrix: number[][];
}

export interface WaggleRevealedProbability {
  index: number;
  probabilityUnits: number;
}

export interface WagglePairwiseDecisionBound {
  opponentActionId: string;
  lowerAdvantageUnits: number;
}

export interface WaggleDecisionCertificate {
  schemaVersion: typeof DECISION_CERTIFICATE_SCHEMA;
  certificateId: string;
  caseId: string;
  policyId: string;
  vectorId: string;
  probabilityScale: number;
  sourceProbabilityCount: number;
  maxRevealed: number;
  revealed: WaggleRevealedProbability[];
  residualUnits: number;
  disposition: "continue" | "insufficient_confidence";
  actionId: string | null;
  pairwiseLowerAdvantages: WagglePairwiseDecisionBound[];
  authorityGranted: false;
}

export interface WaggleReferenceDecision {
  disposition: "continue" | "insufficient_confidence";
  actionId: string | null;
  actionCostUnits: number[];
}

const SYMBOLIC_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,159}$/;
const MAX_LABELS = 1_024;
const MAX_ACTIONS = 32;
const MAX_COST_UNITS = 1_000_000;

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function requireInteger(value: unknown, path: string, minimum: number, maximum: number): asserts value is number {
  requireCondition(Number.isSafeInteger(value), `${path} must be a safe integer`);
  requireCondition((value as number) >= minimum && (value as number) <= maximum, `${path} is outside range`);
}

function policyBody(input: Omit<WaggleDecisionPolicy, "policyId">) {
  return {
    schemaVersion: input.schemaVersion,
    labelIds: input.labelIds,
    actionIds: input.actionIds,
    costMatrix: input.costMatrix,
  };
}

export function createDecisionPolicy(input: {
  labelIds: string[];
  actionIds: string[];
  costMatrix: number[][];
}): WaggleDecisionPolicy {
  const body = {
    schemaVersion: DECISION_POLICY_SCHEMA,
    labelIds: structuredClone(input.labelIds),
    actionIds: structuredClone(input.actionIds),
    costMatrix: structuredClone(input.costMatrix),
  };
  const policy: WaggleDecisionPolicy = {
    ...body,
    policyId: contentId("decisionpolicy", body),
  };
  assertDecisionPolicy(policy);
  return policy;
}

export function validateDecisionPolicy(value: unknown): string[] {
  const errors: string[] = [];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return ["policy must be a plain object"];
  }
  const policy = value as Partial<WaggleDecisionPolicy>;
  const expectedKeys = ["actionIds", "costMatrix", "labelIds", "policyId", "schemaVersion"];
  const observedKeys = Object.keys(policy).sort();
  if (canonicalJson(observedKeys) !== canonicalJson(expectedKeys)) {
    errors.push("policy fields are not canonical");
  }
  if (policy.schemaVersion !== DECISION_POLICY_SCHEMA) errors.push("policy schemaVersion is invalid");
  if (typeof policy.policyId !== "string" || !/^decisionpolicy_[a-f0-9]{20}$/.test(policy.policyId)) {
    errors.push("policyId is invalid");
  }
  if (!Array.isArray(policy.labelIds) || policy.labelIds.length < 2 || policy.labelIds.length > MAX_LABELS) {
    errors.push("labelIds length is invalid");
  } else {
    if (new Set(policy.labelIds).size !== policy.labelIds.length) errors.push("labelIds must be unique");
    if (policy.labelIds.some((item) => typeof item !== "string" || !SYMBOLIC_ID.test(item))) {
      errors.push("labelIds must be symbolic identifiers");
    }
  }
  if (!Array.isArray(policy.actionIds) || policy.actionIds.length < 2 || policy.actionIds.length > MAX_ACTIONS) {
    errors.push("actionIds length is invalid");
  } else {
    if (new Set(policy.actionIds).size !== policy.actionIds.length) errors.push("actionIds must be unique");
    if (policy.actionIds.some((item) => typeof item !== "string" || !SYMBOLIC_ID.test(item))) {
      errors.push("actionIds must be symbolic identifiers");
    }
  }
  if (!Array.isArray(policy.costMatrix) || !Array.isArray(policy.actionIds) || policy.costMatrix.length !== policy.actionIds.length) {
    errors.push("costMatrix action dimension is invalid");
  } else if (Array.isArray(policy.labelIds)) {
    policy.costMatrix.forEach((row, actionIndex) => {
      if (!Array.isArray(row) || row.length !== policy.labelIds!.length) {
        errors.push(`costMatrix[${actionIndex}] label dimension is invalid`);
        return;
      }
      row.forEach((cost, labelIndex) => {
        if (!Number.isSafeInteger(cost) || cost < 0 || cost > MAX_COST_UNITS) {
          errors.push(`costMatrix[${actionIndex}][${labelIndex}] is invalid`);
        }
      });
    });
  }
  if (errors.length === 0) {
    const expectedId = contentId("decisionpolicy", policyBody(policy as WaggleDecisionPolicy));
    if (policy.policyId !== expectedId) errors.push("policyId does not match policy content");
  }
  return errors;
}

export function assertDecisionPolicy(value: unknown): asserts value is WaggleDecisionPolicy {
  const errors = validateDecisionPolicy(value);
  if (errors.length) throw new Error(`Invalid decision policy: ${errors.join("; ")}`);
}

export function validateProbabilityVector(probabilities: readonly number[], scale: number, labelCount?: number): void {
  requireInteger(scale, "probabilityScale", 1, 1_000_000_000);
  requireCondition(Array.isArray(probabilities), "probabilities must be an array");
  if (labelCount !== undefined) requireCondition(probabilities.length === labelCount, "probability vector length mismatch");
  requireCondition(probabilities.length >= 2 && probabilities.length <= MAX_LABELS, "probability vector length is invalid");
  let sum = 0;
  probabilities.forEach((value, index) => {
    requireInteger(value, `probabilities[${index}]`, 0, scale);
    sum += value;
  });
  requireCondition(sum === scale, `probability vector must sum exactly to ${scale}`);
}

export function decisionVectorId(probabilities: readonly number[], probabilityScale: number): string {
  validateProbabilityVector(probabilities, probabilityScale);
  return contentId("decisionvector", { probabilityScale, probabilities });
}

export function referenceDecision(
  probabilities: readonly number[],
  probabilityScale: number,
  policy: WaggleDecisionPolicy
): WaggleReferenceDecision {
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

function certifiedAction(
  revealed: readonly WaggleRevealedProbability[],
  residualUnits: number,
  policy: WaggleDecisionPolicy
): { actionId: string; bounds: WagglePairwiseDecisionBound[] } | null {
  const revealedIndexes = new Set(revealed.map((item) => item.index));
  const omittedIndexes = policy.labelIds
    .map((_, index) => index)
    .filter((index) => !revealedIndexes.has(index));
  const candidates: Array<{ actionId: string; bounds: WagglePairwiseDecisionBound[] }> = [];

  policy.actionIds.forEach((actionId, candidateIndex) => {
    const bounds: WagglePairwiseDecisionBound[] = [];
    let valid = true;
    policy.actionIds.forEach((opponentActionId, opponentIndex) => {
      if (candidateIndex === opponentIndex) return;
      const knownAdvantage = revealed.reduce(
        (sum, item) =>
          sum +
          item.probabilityUnits *
            (policy.costMatrix[opponentIndex][item.index] - policy.costMatrix[candidateIndex][item.index]),
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

function certificateBody(value: Omit<WaggleDecisionCertificate, "certificateId">) {
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

export function createDecisionCertificate(input: {
  caseId: string;
  probabilities: readonly number[];
  probabilityScale: number;
  policy: WaggleDecisionPolicy;
  maxRevealed: number;
}): WaggleDecisionCertificate {
  assertDecisionPolicy(input.policy);
  requireCondition(SYMBOLIC_ID.test(input.caseId), "caseId must be a symbolic identifier");
  validateProbabilityVector(input.probabilities, input.probabilityScale, input.policy.labelIds.length);
  requireInteger(input.maxRevealed, "maxRevealed", 1, input.probabilities.length);

  const ranking = input.probabilities
    .map((probabilityUnits, index) => ({ index, probabilityUnits }))
    .sort((left, right) => right.probabilityUnits - left.probabilityUnits || left.index - right.index);
  let selected = ranking.slice(0, input.maxRevealed);
  let result: ReturnType<typeof certifiedAction> = null;
  for (let count = 1; count <= input.maxRevealed; count += 1) {
    const candidate = ranking.slice(0, count);
    const residualUnits = input.probabilityScale - candidate.reduce((sum, item) => sum + item.probabilityUnits, 0);
    const certified = certifiedAction(candidate, residualUnits, input.policy);
    if (certified) {
      selected = candidate;
      result = certified;
      break;
    }
  }
  const residualUnits = input.probabilityScale - selected.reduce((sum, item) => sum + item.probabilityUnits, 0);
  const body: Omit<WaggleDecisionCertificate, "certificateId"> = {
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

export function verifyDecisionCertificateMath(
  certificate: WaggleDecisionCertificate,
  policy: WaggleDecisionPolicy
): string[] {
  const errors: string[] = [];
  try {
    assertDecisionPolicy(policy);
    requireCondition(certificate !== null && typeof certificate === "object" && !Array.isArray(certificate), "certificate must be an object");
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
    requireCondition(canonicalJson(Object.keys(certificate).sort()) === canonicalJson(expectedKeys), "certificate fields are not canonical");
    requireCondition(certificate.schemaVersion === DECISION_CERTIFICATE_SCHEMA, "certificate schemaVersion is invalid");
    requireCondition(/^decisioncert_[a-f0-9]{20}$/.test(certificate.certificateId), "certificateId is invalid");
    requireCondition(SYMBOLIC_ID.test(certificate.caseId), "certificate caseId is invalid");
    requireCondition(certificate.policyId === policy.policyId, "certificate policyId mismatch");
    requireCondition(/^decisionvector_[a-f0-9]{20}$/.test(certificate.vectorId), "certificate vectorId is invalid");
    requireInteger(certificate.probabilityScale, "certificate.probabilityScale", 1, 1_000_000_000);
    requireInteger(certificate.sourceProbabilityCount, "certificate.sourceProbabilityCount", 2, MAX_LABELS);
    requireCondition(certificate.sourceProbabilityCount === policy.labelIds.length, "certificate label count mismatch");
    requireInteger(certificate.maxRevealed, "certificate.maxRevealed", 1, certificate.sourceProbabilityCount);
    requireCondition(Array.isArray(certificate.revealed), "certificate revealed must be an array");
    requireCondition(certificate.revealed.length >= 1 && certificate.revealed.length <= certificate.maxRevealed, "certificate revealed length is invalid");
    const indexes = new Set<number>();
    certificate.revealed.forEach((item, rank) => {
      requireCondition(item !== null && typeof item === "object" && !Array.isArray(item), `certificate.revealed[${rank}] is invalid`);
      requireCondition(canonicalJson(Object.keys(item).sort()) === canonicalJson(["index", "probabilityUnits"]), `certificate.revealed[${rank}] fields are invalid`);
      requireInteger(item.index, `certificate.revealed[${rank}].index`, 0, certificate.sourceProbabilityCount - 1);
      requireInteger(item.probabilityUnits, `certificate.revealed[${rank}].probabilityUnits`, 0, certificate.probabilityScale);
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
    requireCondition(revealedSum + certificate.residualUnits === certificate.probabilityScale, "certificate probability mass is inconsistent");
    requireCondition(certificate.authorityGranted === false, "certificate cannot grant authority");
    const recomputed = certifiedAction(certificate.revealed, certificate.residualUnits, policy);
    const expectedDisposition = recomputed ? "continue" : "insufficient_confidence";
    requireCondition(certificate.disposition === expectedDisposition, "certificate disposition does not match bounds");
    requireCondition(certificate.actionId === (recomputed?.actionId ?? null), "certificate action does not match bounds");
    requireCondition(
      canonicalJson(certificate.pairwiseLowerAdvantages) === canonicalJson(recomputed?.bounds ?? []),
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

export function decisionStateBytes(value: unknown): number {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

export function decisionStateHash(value: unknown): string {
  return hashCanonical(value);
}
