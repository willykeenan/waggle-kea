import { canonicalJson, contentId } from "./canonical.js";
import {
  createDecisionCertificate,
  decisionVectorId,
  referenceDecision,
  verifyDecisionCertificateMath,
  type WaggleDecisionCertificate,
  type WaggleDecisionPolicy,
} from "../waggle/decision-certificate.js";

export interface KeaDecisionQualification {
  schemaVersion: "kea.decision-qualification.v1";
  qualificationId: string;
  certificateId: string;
  policyId: string;
  vectorId: string;
  disposition: "qualified" | "abstained" | "rejected";
  sourceVectorVerified: boolean;
  certificateMathVerified: boolean;
  referenceDecisionMatched: boolean;
  errors: string[];
  authorityGranted: false;
}

export interface KeaRestrictedDecision {
  schemaVersion: "kea.restricted-decision.v1";
  disposition: "continue" | "insufficient_confidence" | "abstain";
  actionId: string | null;
  certificateId: string;
  qualificationId: string;
  authorityGranted: false;
}

function qualificationBody(value: Omit<KeaDecisionQualification, "qualificationId">) {
  return {
    schemaVersion: value.schemaVersion,
    certificateId: value.certificateId,
    policyId: value.policyId,
    vectorId: value.vectorId,
    disposition: value.disposition,
    sourceVectorVerified: value.sourceVectorVerified,
    certificateMathVerified: value.certificateMathVerified,
    referenceDecisionMatched: value.referenceDecisionMatched,
    errors: value.errors,
    authorityGranted: value.authorityGranted,
  };
}

export function qualifyDecisionCertificate(input: {
  certificate: WaggleDecisionCertificate;
  policy: WaggleDecisionPolicy;
  fullProbabilityVector: readonly number[];
}): KeaDecisionQualification {
  const errors = verifyDecisionCertificateMath(input.certificate, input.policy);
  let sourceVectorVerified = false;
  let referenceDecisionMatched = false;
  try {
    const observedVectorId = decisionVectorId(
      input.fullProbabilityVector,
      input.certificate.probabilityScale
    );
    sourceVectorVerified = observedVectorId === input.certificate.vectorId;
    if (!sourceVectorVerified) errors.push("certificate vectorId does not match the source vector");

    const expected = createDecisionCertificate({
      caseId: input.certificate.caseId,
      probabilities: input.fullProbabilityVector,
      probabilityScale: input.certificate.probabilityScale,
      policy: input.policy,
      maxRevealed: input.certificate.maxRevealed,
    });
    if (canonicalJson(expected) !== canonicalJson(input.certificate)) {
      errors.push("certificate is not the canonical minimal-prefix certificate for the source vector");
    }

    const reference = referenceDecision(
      input.fullProbabilityVector,
      input.certificate.probabilityScale,
      input.policy
    );
    referenceDecisionMatched =
      input.certificate.disposition === "insufficient_confidence" ||
      (reference.disposition === "continue" && reference.actionId === input.certificate.actionId);
    if (!referenceDecisionMatched) errors.push("certificate decision does not match the full-vector reference");
  } catch (error) {
    errors.push(error instanceof Error ? error.message : String(error));
  }

  const body: Omit<KeaDecisionQualification, "qualificationId"> = {
    schemaVersion: "kea.decision-qualification.v1",
    certificateId: input.certificate.certificateId,
    policyId: input.certificate.policyId,
    vectorId: input.certificate.vectorId,
    disposition:
      errors.length > 0
        ? "rejected"
        : input.certificate.disposition === "continue"
          ? "qualified"
          : "abstained",
    sourceVectorVerified,
    certificateMathVerified: errors.length === 0,
    referenceDecisionMatched,
    errors,
    authorityGranted: false,
  };
  return { ...body, qualificationId: contentId("keaqualification", body) };
}

export function consumeQualifiedDecision(input: {
  certificate: WaggleDecisionCertificate;
  policy: WaggleDecisionPolicy;
  qualification: KeaDecisionQualification;
}): KeaRestrictedDecision {
  const mathErrors = verifyDecisionCertificateMath(input.certificate, input.policy);
  const qualificationId = contentId("keaqualification", qualificationBody(input.qualification));
  const validQualification =
    qualificationId === input.qualification.qualificationId &&
    input.qualification.certificateId === input.certificate.certificateId &&
    input.qualification.policyId === input.policy.policyId &&
    input.qualification.vectorId === input.certificate.vectorId &&
    input.qualification.authorityGranted === false &&
    input.qualification.errors.length === 0;

  let disposition: KeaRestrictedDecision["disposition"] = "abstain";
  let actionId: string | null = null;
  if (mathErrors.length === 0 && validQualification) {
    if (
      input.qualification.disposition === "qualified" &&
      input.qualification.sourceVectorVerified &&
      input.qualification.certificateMathVerified &&
      input.qualification.referenceDecisionMatched &&
      input.certificate.disposition === "continue"
    ) {
      disposition = "continue";
      actionId = input.certificate.actionId;
    } else if (
      input.qualification.disposition === "abstained" &&
      input.qualification.sourceVectorVerified &&
      input.qualification.certificateMathVerified &&
      input.qualification.referenceDecisionMatched &&
      input.certificate.disposition === "insufficient_confidence"
    ) {
      disposition = "insufficient_confidence";
    }
  }

  return {
    schemaVersion: "kea.restricted-decision.v1",
    disposition,
    actionId,
    certificateId: input.certificate.certificateId,
    qualificationId: input.qualification.qualificationId,
    authorityGranted: false,
  };
}
