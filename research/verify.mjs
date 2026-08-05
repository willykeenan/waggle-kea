import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const summary = JSON.parse(readFileSync(join(root, "data/c15d-summary.json"), "utf8"));

assert.equal(summary.author, "William Keenan");
assert.equal(summary.researchContext, "independent");
assert.equal(summary.quality.residentNativeExact, summary.quality.informedTasksPerArm);
assert.equal(summary.quality.noStateAbstained, summary.workload.tasks);
assert.equal(summary.breakEvenBranch.versusResidentFullText, 3);
assert.equal(summary.breakEvenBranch.versusResidentCachedText, null);
assert.equal(summary.breakEvenBranch.versusFreshNative, null);
assert.equal(summary.claims.hardwareNativeReuseMechanism, true);
assert.equal(summary.claims.separateKeaQualification, true);
assert.equal(summary.claims.overallEfficiency, false);
assert.equal(summary.claims.tokenSavings, false);
assert.equal(summary.claims.production, false);
assert.equal(summary.authority.externalCalls, 0);
assert.equal(summary.authority.authorityEffectsExecuted, 0);
assert.equal(summary.authority.authorityGranted, false);

const forbidden = [
  new RegExp(["ke", "studios\\.dev"].join(""), "i"),
  new RegExp(["ke", "studios"].join(" "), "i"),
  new RegExp(["private", "Product", "Commit"].join(""), "i"),
  new RegExp(["/", "Users", "/"].join("")),
  new RegExp(["@", "gmail\\.com"].join(""), "i"),
];

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : statSync(path).isFile() ? [path] : [];
  });
}

for (const path of files(root)) {
  if (path.endsWith("SHA256SUMS")) continue;
  const value = readFileSync(path, "utf8");
  for (const pattern of forbidden) {
    assert.equal(pattern.test(value), false, `${relative(root, path)} contains ${pattern}`);
  }
}

const checksums = readFileSync(join(root, "SHA256SUMS"), "utf8").trim().split("\n");
for (const line of checksums) {
  const match = line.match(/^([a-f0-9]{64}) \*(research\/.+)$/);
  assert.ok(match, `invalid checksum line: ${line}`);
  const [, expected, file] = match;
  const actual = createHash("sha256")
    .update(readFileSync(join(root, "..", file)))
    .digest("hex");
  assert.equal(actual, expected, `${file} checksum mismatch`);
}

console.log("research verification: passed");
