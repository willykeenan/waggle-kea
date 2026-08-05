import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const resultRoot = resolve(repoRoot, "benchmarks/banking77/results/reference-v1");

test("the committed BANKING77 reference evidence passes its fail-closed verifier", () => {
  const result = spawnSync(
    process.execPath,
    [resolve(repoRoot, "scripts/verify-banking77-benchmark.mjs")],
    { cwd: repoRoot, encoding: "utf8" }
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const summary = JSON.parse(result.stdout.trim()) as { ok: boolean; primaryTestCases: number };
  assert.equal(summary.ok, true);
  assert.equal(summary.primaryTestCases, 3050);
});
test("classification and handoff results remain separate, bounded claims", () => {
  const run = JSON.parse(readFileSync(resolve(resultRoot, "run.json"), "utf8"));
  const handoff = JSON.parse(readFileSync(resolve(resultRoot, "handoff.json"), "utf8"));

  assert.equal(run.status, "exploratory-valid");
  assert.equal(run.preRegistered, false);
  assert.equal(run.testInformedDesign, true);
  assert.ok(["H1_SUPPORTED_EXPLORATORY", "H0_RETAINED"].includes(run.scientificVerdict));
  assert.equal(run.effects.providerApiCalls, 0);
  assert.equal(run.effects.authorityEffectsExecuted, 0);
  assert.ok(run.nonClaims.some((claim: string) => claim.includes("HSBC")));
  assert.ok(run.nonClaims.some((claim: string) => claim.includes("private Qwen")));

  assert.equal(handoff.status, "passed");
  assert.equal(handoff.informationParity.disagreementCount, 0);
  assert.equal(handoff.faults.detectableFaultFalseAccepts, 0);
  assert.equal(handoff.clean.authorityGrants, 0);
  assert.equal(handoff.rehashedForgeryControl.expectedDetected, false);
  assert.equal(handoff.rehashedForgeryControl.detected, false);
});
