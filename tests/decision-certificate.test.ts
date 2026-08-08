import assert from "node:assert/strict";
import { test } from "node:test";

import {
  canonicalJson,
  consumeQualifiedDecision,
  createDecisionCertificate,
  createDecisionPolicy,
  qualifyDecisionCertificate,
  referenceDecision,
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
