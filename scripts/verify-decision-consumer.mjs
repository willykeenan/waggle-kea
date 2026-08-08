#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const argv = process.argv.slice(2);
const flag = argv.indexOf("--results");
if (flag < 0 || !argv[flag + 1]) {
  process.stderr.write("usage: verify-decision-consumer.mjs --results <dir>\n");
  process.exit(2);
}
const results = resolve(argv[flag + 1]);
const sample = JSON.parse(readFileSync(join(results, "samples.jsonl"), "utf8").split("\n").find(Boolean));
const policies = JSON.parse(readFileSync(join(results, "policies.json"), "utf8"));
const policy = policies.policies.find((item) => item.policyId === sample.policyId);
if (!policy) throw new Error("sample policy missing");

const isolated = mkdtempSync(join(tmpdir(), "waggle-consumer-evidence-"));
try {
  const inputPath = join(isolated, "input.json");
  writeFileSync(
    inputPath,
    `${canonical({
      schemaVersion: "waggle.restricted-consumer-input.v1",
      certificate: sample.certificate,
      policy,
      qualification: sample.qualification,
      authorityGranted: false,
    })}\n`,
    "utf8"
  );
  const result = spawnSync("npx", ["tsx", "scripts/consume-decision-certificate.ts", "--input", inputPath], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 30_000,
  });
  if (result.status !== 0) throw new Error(`${result.stdout}${result.stderr}`);
  const observed = JSON.parse(result.stdout);
  const expectedKeys = [
    "actionId",
    "authorityGranted",
    "certificateId",
    "disposition",
    "qualificationId",
    "schemaVersion",
  ];
  if (canonical(Object.keys(observed).sort()) !== canonical(expectedKeys)) {
    throw new Error("fresh restricted consumer receipt fields drifted");
  }
  if (
    observed.schemaVersion !== "kea.restricted-decision.v1" ||
    observed.certificateId !== sample.certificate.certificateId ||
    observed.qualificationId !== sample.qualification.qualificationId ||
    observed.authorityGranted !== false
  ) {
    throw new Error("fresh restricted consumer receipt lineage drifted");
  }
  const observedProjection = {
    disposition: observed.disposition,
    actionId: observed.actionId,
    authorityGranted: observed.authorityGranted,
  };
  if (canonical(observedProjection) !== canonical(sample.restricted)) {
    throw new Error("fresh restricted consumer disagreed with frozen sample");
  }
  process.stdout.write(
    `${JSON.stringify({
      ok: true,
      caseId: sample.caseId,
      disposition: observed.disposition,
      actionId: observed.actionId,
      sourceVectorReceived: false,
      sourceTextReceived: false,
      authorityGranted: false,
    })}\n`
  );
} finally {
  rmSync(isolated, { recursive: true, force: true });
}
