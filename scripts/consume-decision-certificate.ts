#!/usr/bin/env -S npx tsx

import { lstatSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  canonicalJson,
  consumeQualifiedDecision,
  type KeaDecisionQualification,
  type WaggleDecisionCertificate,
  type WaggleDecisionPolicy,
} from "../src/index.js";

const INPUT_SCHEMA = "waggle.restricted-consumer-input.v1" as const;

interface RestrictedInput {
  schemaVersion: typeof INPUT_SCHEMA;
  certificate: WaggleDecisionCertificate | null;
  policy: WaggleDecisionPolicy | null;
  qualification: KeaDecisionQualification | null;
  authorityGranted: false;
}

function fail(message: string): never {
  process.stderr.write(`restricted consumer rejected input: ${message}\n`);
  process.exit(2);
}

function main(): void {
  const argv = process.argv.slice(2);
  const index = argv.indexOf("--input");
  if (index < 0 || !argv[index + 1] || argv.length !== 2) fail("usage: --input <single-json-file>");
  const path = resolve(argv[index + 1]);
  if (lstatSync(path).isSymbolicLink()) fail("input must not be a symlink");
  const input = JSON.parse(readFileSync(path, "utf8")) as RestrictedInput;
  if (input === null || typeof input !== "object" || Array.isArray(input)) fail("input must be an object");
  const expectedKeys = [
    "authorityGranted",
    "certificate",
    "policy",
    "qualification",
    "schemaVersion",
  ];
  if (canonicalJson(Object.keys(input).sort()) !== canonicalJson(expectedKeys)) {
    fail("input fields are not canonical");
  }
  if (input.schemaVersion !== INPUT_SCHEMA) fail("schemaVersion is invalid");
  if (input.authorityGranted !== false) fail("input cannot grant authority");

  if (input.certificate === null || input.policy === null || input.qualification === null) {
    process.stdout.write(
      `${canonicalJson({
        schemaVersion: "kea.restricted-decision.v1",
        disposition: "abstain",
        actionId: null,
        certificateId: null,
        qualificationId: null,
        authorityGranted: false,
      })}\n`
    );
    return;
  }

  const result = consumeQualifiedDecision({
    certificate: input.certificate,
    policy: input.policy,
    qualification: input.qualification,
  });
  process.stdout.write(`${canonicalJson(result)}\n`);
}

main();
