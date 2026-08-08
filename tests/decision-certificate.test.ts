import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalJson,
  consumeQualifiedDecision,
  createDecisionCertificate,
  createDecisionPolicy,
  qualifyDecisionCertificate,
  referenceDecision,
  validateDecisionQualification,
  verifyDecisionCertificateMath,
} from "../src/index.js";

function fixturePolicy() {
  return createDecisionPolicy({
    labelIds: ["label_a", "label_b", "label_c", "label_d"],
    actionIds: ["queue_left", "queue_right"],
    costMatrix: [
      [0, 0, 1_000, 1_000],
      [1_000, 1_000, 0, 0],
    ],
  });
}

test("a bounded certificate proves the full-vector action from one revealed component", () => {
  const policy = fixturePolicy();
  const probabilities = [700_000, 100_000, 100_000, 100_000];
  const certificate = createDecisionCertificate({
    caseId: "case_constructive",
    probabilities,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });

  assert.equal(referenceDecision(probabilities, 1_000_000, policy).actionId, "queue_left");
  assert.equal(certificate.disposition, "continue");
  assert.equal(certificate.actionId, "queue_left");
  assert.equal(certificate.revealed.length, 1);
  assert.equal(certificate.residualUnits, 300_000);
  assert.deepEqual(verifyDecisionCertificateMath(certificate, policy), []);

  const qualification = qualifyDecisionCertificate({
    certificate,
    policy,
    fullProbabilityVector: probabilities,
  });
  assert.equal(qualification.disposition, "qualified");
  assert.equal(qualification.authorityGranted, false);

  const consumer = consumeQualifiedDecision({ certificate, policy, qualification });
  assert.equal(consumer.disposition, "continue");
  assert.equal(consumer.actionId, "queue_left");
  assert.equal(consumer.authorityGranted, false);
});

test("the certificate reveals more state only when the worst-case residual requires it", () => {
  const policy = fixturePolicy();
  const probabilities = [400_000, 300_000, 200_000, 100_000];
  const certificate = createDecisionCertificate({
    caseId: "case_progressive",
    probabilities,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 2,
  });

  assert.equal(certificate.disposition, "continue");
  assert.equal(certificate.actionId, "queue_left");
  assert.equal(certificate.revealed.length, 2);
  assert.deepEqual(certificate.revealed.map((item) => item.index), [0, 1]);
});

test("an unresolved interval returns insufficient confidence rather than a nominal guess", () => {
  const policy = fixturePolicy();
  const probabilities = [300_000, 200_000, 300_000, 200_000];
  const certificate = createDecisionCertificate({
    caseId: "case_tied",
    probabilities,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });

  assert.equal(referenceDecision(probabilities, 1_000_000, policy).disposition, "insufficient_confidence");
  assert.equal(certificate.disposition, "insufficient_confidence");
  assert.equal(certificate.actionId, null);
  const qualification = qualifyDecisionCertificate({
    certificate,
    policy,
    fullProbabilityVector: probabilities,
  });
  assert.equal(qualification.disposition, "abstained");
  assert.equal(
    consumeQualifiedDecision({ certificate, policy, qualification }).disposition,
    "insufficient_confidence"
  );
});

test("Kea rejects rehashed mathematical, source-vector, and authority forgeries", () => {
  const policy = fixturePolicy();
  const probabilities = [700_000, 100_000, 100_000, 100_000];
  const original = createDecisionCertificate({
    caseId: "case_tamper",
    probabilities,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });

  const badBounds = structuredClone(original);
  badBounds.pairwiseLowerAdvantages[0].lowerAdvantageUnits += 1;
  assert.match(verifyDecisionCertificateMath(badBounds, policy)[0], /pairwise bounds/);

  const wrongVector = qualifyDecisionCertificate({
    certificate: original,
    policy,
    fullProbabilityVector: [600_000, 200_000, 100_000, 100_000],
  });
  assert.equal(wrongVector.disposition, "rejected");
  assert.ok(wrongVector.errors.some((error) => error.includes("vectorId")));

  const qualification = qualifyDecisionCertificate({
    certificate: original,
    policy,
    fullProbabilityVector: probabilities,
  });
  const forgedQualification = structuredClone(qualification) as typeof qualification & {
    authorityGranted: boolean;
  };
  forgedQualification.authorityGranted = true;
  assert.equal(
    consumeQualifiedDecision({ certificate: original, policy, qualification: forgedQualification as typeof qualification })
      .disposition,
    "abstain"
  );

  const rehashedAction = structuredClone(original);
  rehashedAction.actionId = "queue_right";
  rehashedAction.certificateId = original.certificateId;
  assert.notEqual(canonicalJson(rehashedAction), canonicalJson(original));
  assert.ok(verifyDecisionCertificateMath(rehashedAction, policy).length > 0);
});

test("restricted consumer rejects noncanonical and malformed qualifications without throwing", () => {
  const policy = fixturePolicy();
  const probabilities = [700_000, 100_000, 100_000, 100_000];
  const certificate = createDecisionCertificate({
    caseId: "case_qualification_shape",
    probabilities,
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });
  const qualification = qualifyDecisionCertificate({ certificate, policy, fullProbabilityVector: probabilities });

  const extra = { ...structuredClone(qualification), smuggled: true };
  assert.match(validateDecisionQualification(extra)[0], /fields are not canonical/);
  assert.equal(
    consumeQualifiedDecision({ certificate, policy, qualification: extra as typeof qualification }).disposition,
    "abstain"
  );

  const malformed = { ...structuredClone(qualification), errors: null };
  assert.ok(validateDecisionQualification(malformed).some((error) => error.includes("string array")));
  assert.doesNotThrow(() =>
    consumeQualifiedDecision({ certificate, policy, qualification: malformed as unknown as typeof qualification })
  );
  assert.equal(
    consumeQualifiedDecision({ certificate, policy, qualification: malformed as unknown as typeof qualification })
      .disposition,
    "abstain"
  );
});

function compositions(total: number, parts: number): number[][] {
  if (parts === 1) return [[total]];
  const output: number[][] = [];
  for (let first = 0; first <= total; first += 1) {
    for (const rest of compositions(total - first, parts - 1)) output.push([first, ...rest]);
  }
  return output;
}

test("certificate bound is exact against exhaustive small-simplex completions", () => {
  const policies = [
    createDecisionPolicy({
      labelIds: ["l0", "l1", "l2", "l3"],
      actionIds: ["a0", "a1", "a2"],
      costMatrix: [
        [0, 3, 1, 2],
        [2, 0, 3, 1],
        [3, 2, 0, 2],
      ],
    }),
    createDecisionPolicy({
      labelIds: ["l0", "l1", "l2", "l3"],
      actionIds: ["a0", "a1", "a2"],
      costMatrix: [
        [1, 0, 4, 2],
        [0, 3, 1, 4],
        [3, 2, 0, 1],
      ],
    }),
  ];
  const scale = 6;
  for (const policy of policies) {
    for (const vector of compositions(scale, 4)) {
      for (const maxRevealed of [1, 2, 3]) {
        const certificate = createDecisionCertificate({
          caseId: "case_exhaustive",
          probabilities: vector,
          probabilityScale: scale,
          policy,
          maxRevealed,
        });
        const revealed = new Map(certificate.revealed.map((item) => [item.index, item.probabilityUnits]));
        const omitted = [0, 1, 2, 3].filter((index) => !revealed.has(index));
        const completionActions = new Set<string | null>();
        for (const allocation of compositions(certificate.residualUnits, omitted.length)) {
          const completion = Array(4).fill(0) as number[];
          for (const [index, value] of revealed) completion[index] = value;
          omitted.forEach((index, offset) => {
            completion[index] = allocation[offset];
          });
          completionActions.add(referenceDecision(completion, scale, policy).actionId);
        }
        if (certificate.disposition === "continue") {
          assert.deepEqual([...completionActions], [certificate.actionId]);
        } else {
          assert.ok(
            completionActions.size !== 1 || completionActions.has(null),
            `uncertified prefix unexpectedly forced ${[...completionActions].join(",")}`
          );
        }
      }
    }
  }
});

test("noncanonical vectors, policies, and certificate identities fail closed", () => {
  const policy = fixturePolicy();
  assert.throws(
    () =>
      createDecisionCertificate({
        caseId: "case_bad_sum",
        probabilities: [700_000, 100_000, 100_000, 99_999],
        probabilityScale: 1_000_000,
        policy,
        maxRevealed: 3,
      }),
    /sum exactly/
  );
  assert.throws(
    () =>
      createDecisionPolicy({
        labelIds: ["duplicate", "duplicate"],
        actionIds: ["left", "right"],
        costMatrix: [
          [0, 1],
          [1, 0],
        ],
      }),
    /labelIds must be unique/
  );

  const certificate = createDecisionCertificate({
    caseId: "case_identity",
    probabilities: [700_000, 100_000, 100_000, 100_000],
    probabilityScale: 1_000_000,
    policy,
    maxRevealed: 3,
  });
  certificate.certificateId = `decisioncert_${"0".repeat(20)}`;
  assert.match(verifyDecisionCertificateMath(certificate, policy)[0], /certificateId/);
});
