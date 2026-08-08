import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

import {
  canonicalJson,
  createDecisionCertificate,
  createDecisionPolicy,
  qualifyDecisionCertificate,
} from "../src/index.js";

const consumer = resolve("scripts/consume-decision-certificate.ts");

function run(input: unknown) {
  const root = mkdtempSync(join(tmpdir(), "waggle-restricted-consumer-"));
  try {
    const path = join(root, "input.json");
    writeFileSync(path, `${canonicalJson(input)}\n`, "utf8");
    return spawnSync("npx", ["tsx", consumer, "--input", path], {
      cwd: process.cwd(),
      encoding: "utf8",
      timeout: 30_000,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function policy() {
  return createDecisionPolicy({
    labelIds: ["l0", "l1", "l2", "l3"],
    actionIds: ["left", "right"],
    costMatrix: [
      [0, 0, 1_000, 1_000],
      [1_000, 1_000, 0, 0],
    ],
  });
}

test("fresh restricted consumer continues, refuses, and abstains without source state", () => {
  const frozenPolicy = policy();
  for (const fixture of [
    { probabilities: [700_000, 100_000, 100_000, 100_000], expected: "continue" },
    { probabilities: [300_000, 200_000, 300_000, 200_000], expected: "insufficient_confidence" },
  ] as const) {
    const certificate = createDecisionCertificate({
      caseId: `case_${fixture.expected}`,
      probabilities: fixture.probabilities,
      probabilityScale: 1_000_000,
      policy: frozenPolicy,
      maxRevealed: 3,
    });
    const qualification = qualifyDecisionCertificate({
      certificate,
      policy: frozenPolicy,
      fullProbabilityVector: fixture.probabilities,
    });
    const result = run({
      schemaVersion: "waggle.restricted-consumer-input.v1",
      certificate,
      policy: frozenPolicy,
      qualification,
      authorityGranted: false,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).disposition, fixture.expected);
    assert.equal(JSON.parse(result.stdout).authorityGranted, false);
  }

  const noState = run({
    schemaVersion: "waggle.restricted-consumer-input.v1",
    certificate: null,
    policy: null,
    qualification: null,
    authorityGranted: false,
  });
  assert.equal(noState.status, 0, noState.stderr);
  assert.equal(JSON.parse(noState.stdout).disposition, "abstain");
});

test("fresh restricted consumer rejects extra fields and authority smuggling", () => {
  const extra = run({
    schemaVersion: "waggle.restricted-consumer-input.v1",
    certificate: null,
    policy: null,
    qualification: null,
    authorityGranted: false,
    expectedAction: "left",
  });
  assert.equal(extra.status, 2);
  assert.match(extra.stderr, /fields are not canonical/);

  const authority = run({
    schemaVersion: "waggle.restricted-consumer-input.v1",
    certificate: null,
    policy: null,
    qualification: null,
    authorityGranted: true,
  });
  assert.equal(authority.status, 2);
  assert.match(authority.stderr, /cannot grant authority/);
});
