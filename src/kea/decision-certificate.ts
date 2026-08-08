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

export function validateDecisionQualification(value: unknown): string[] {
  const errors: string[] = [];
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return ["qualification must be a plain object"];
  }
  const qualification = value as Partial<KeaDecisionQualification>;
  const expectedKeys = [
    "authorityGranted",
    "certificateId",
    "certificateMathVerified",
    "disposition",
    "errors",
    "policyId",
    "qualificationId",
    "referenceDecisionMatched",
    "schemaVersion",
    "sourceVectorVerified",
    "vectorId",
  ];
  if (canonicalJson(Object.keys(qualification).sort()) !== canonicalJson(expectedKeys)) {
    errors.push("qualification fields are not canonical");
  }
  if (qualification.schemaVersion !== "kea.decision-qualification.v1") {
    errors.push("qualification schemaVersion is invalid");
  }
  if (
    typeof qualification.qualificationId !== "string" ||
    !/^keaqualification_[a-f0-9]{20}$/.test(qualification.qualificationId)
  ) {
    errors.push("qualificationId is invalid");
  }
  if (
    typeof qualification.certificateId !== "string" ||
    !/^decisioncert_[a-f0-9]{20}$/.test(qualification.certificateId)
  ) {
    errors.push("qualification certificateId is invalid");
  }
  if (
    typeof qualification.policyId !== "string" ||
    !/^decisionpolicy_[a-f0-9]{20}$/.test(qualification.policyId)
  ) {
    errors.push("qualification policyId is invalid");
  }
  if (
    typeof qualification.vectorId !== "string" ||
    !/^decisionvector_[a-f0-9]{20}$/.test(qualification.vectorId)
  ) {
    errors.push("qualification vectorId is invalid");
  }
  if (!(["qualified", "abstained", "rejected"] as const).includes(qualification.disposition as never)) {
    errors.push("qualification disposition is invalid");
  }
  for (const key of [
    "sourceVectorVerified",
    "certificateMathVerified",
    "referenceDecisionMatched",
  ] as const) {
    if (typeof qualification[key] !== "boolean") errors.push(`qualification ${key} is invalid`);
  }
  if (!Array.isArray(qualification.errors) || qualification.errors.some((item) => typeof item !== "string")) {
    errors.push("qualification errors must be a string array");
  }
  if (qualification.authorityGranted !== false) errors.push("qualification cannot grant authority");
  if (errors.length === 0) {
    const expectedId = contentId(
      "keaqualification",
      qualificationBody(qualification as KeaDecisionQualification)
    );
    if (qualification.qualificationId !== expectedId) {
      errors.push("qualificationId does not match qualification content");
    }
  }
  return errors;
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
  const qualificationErrors = validateDecisionQualification(input.qualification);
  const validQualification =
    qualificationErrors.length === 0 &&
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
    qualificationId:
      typeof input.qualification?.qualificationId === "string"
        ? input.qualification.qualificationId
        : `keaqualification_${"0".repeat(20)}`,
    authorityGranted: false,
  };
}
