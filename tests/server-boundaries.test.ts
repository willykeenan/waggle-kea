import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { startKeaServer } from "../src/kea/server.js";

interface StatusSnapshot {
  ledgerEvents: number;
  messages: number;
  interpretations: number;
  corrections: number;
}

async function responseJson(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

async function statusSnapshot(baseUrl: string): Promise<StatusSnapshot> {
  const response = await fetch(`${baseUrl}/api/status`);
  assert.equal(response.status, 200);
  const body = await responseJson(response);
  return {
    ledgerEvents: Number(body.ledgerEvents),
    messages: Number(body.messages),
    interpretations: Number(body.interpretations),
    corrections: Number(body.corrections),
  };
}

async function withServer(
  allowFixtureWrites: boolean,
  run: (input: { baseUrl: string; root: string }) => Promise<void>
): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), "kea-server-boundary-"));
  const server = await startKeaServer({ root, host: "127.0.0.1", port: 0, allowFixtureWrites });
  try {
    assert.equal(server.host, "127.0.0.1");
    assert.ok(server.port > 0);
    await run({ baseUrl: `http://${server.host}:${server.port}`, root });
  } finally {
    await server.close();
    rmSync(root, { recursive: true, force: true });
  }
}

test("the ephemeral loopback server is read-only unless fixture writes are explicit", async () => {
  await withServer(false, async ({ baseUrl, root }) => {
    const before = await statusSnapshot(baseUrl);
    assert.deepEqual(before, { ledgerEvents: 0, messages: 0, interpretations: 0, corrections: 0 });

    const denied = await fetch(`${baseUrl}/api/fixtures/interpret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload: { intent: "inspect", operation: "case.review" } }),
    });
    assert.equal(denied.status, 403);
    assert.match(String((await responseJson(denied)).error), /disabled/);

    const wrongReadMethod = await fetch(`${baseUrl}/api/status`, { method: "POST" });
    assert.equal(wrongReadMethod.status, 405);
    assert.equal(wrongReadMethod.headers.get("allow"), "GET");

    const wrongWriteMethod = await fetch(`${baseUrl}/api/fixtures/interpret`);
    assert.equal(wrongWriteMethod.status, 405);
    assert.equal(wrongWriteMethod.headers.get("allow"), "POST");

    const missingRoute = await fetch(`${baseUrl}/api/not-present`);
    assert.equal(missingRoute.status, 404);

    const missingReplay = await fetch(`${baseUrl}/api/replay/not-present`);
    assert.equal(missingReplay.status, 404);
    assert.deepEqual(await responseJson(missingReplay), { error: "Replay not found" });

    assert.deepEqual(await statusSnapshot(baseUrl), before);
    assert.equal(existsSync(join(root, "ledger.jsonl")), false);
  });
});

test("message limits accept one canonical integer from 1 through 500", async () => {
  await withServer(false, async ({ baseUrl }) => {
    for (const query of [
      "limit=0",
      "limit=-1",
      "limit=01",
      "limit=1.0",
      "limit=1e2",
      "limit=%201",
      "limit=501",
      "limit=9007199254740992",
      "limit=1&limit=2",
    ]) {
      const response = await fetch(`${baseUrl}/api/messages?${query}`);
      assert.equal(response.status, 400, query);
      assert.deepEqual(await responseJson(response), {
        error: "limit must be one integer from 1 through 500",
      });
    }

    for (const query of ["", "?limit=1", "?limit=500"]) {
      const response = await fetch(`${baseUrl}/api/messages${query}`);
      assert.equal(response.status, 200, query);
      assert.deepEqual(await responseJson(response), { messages: [] });
    }

    assert.deepEqual(await statusSnapshot(baseUrl), {
      ledgerEvents: 0,
      messages: 0,
      interpretations: 0,
      corrections: 0,
    });
  });
});

test("explicit fixture mode writes valid input and never mutates state for failed input", async () => {
  await withServer(true, async ({ baseUrl }) => {
    const created = await fetch(`${baseUrl}/api/fixtures/interpret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        payload: {
          intent: "inspect",
          operation: "case.review",
          references: ["fixture_case_1"],
        },
      }),
    });
    assert.equal(created.status, 201);
    const createdBody = await responseJson(created);
    assert.equal((createdBody.interpretation as { disposition?: string }).disposition, "verified");

    const afterValidWrite = await statusSnapshot(baseUrl);
    assert.deepEqual(afterValidWrite, {
      ledgerEvents: 2,
      messages: 1,
      interpretations: 1,
      corrections: 0,
    });

    const malformed = await fetch(`${baseUrl}/api/fixtures/interpret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"payload":',
    });
    assert.equal(malformed.status, 400);
    assert.deepEqual(await responseJson(malformed), { error: "Malformed JSON body" });

    const missingPayload = await fetch(`${baseUrl}/api/fixtures/interpret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(missingPayload.status, 400);

    const oversized = await fetch(`${baseUrl}/api/fixtures/interpret`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload: { value: "x".repeat(1_000_000) } }),
    });
    assert.equal(oversized.status, 413);
    assert.deepEqual(await responseJson(oversized), {
      error: "Kea fixture body exceeds 1 MB",
    });

    const unknownCorrection = await fetch(`${baseUrl}/api/fixtures/correct`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        interpretationId: "kea_missing",
        actorId: "human_reviewer",
        humanGloss: "No matching interpretation",
        reason: "boundary test",
      }),
    });
    assert.equal(unknownCorrection.status, 404);

    assert.deepEqual(await statusSnapshot(baseUrl), afterValidWrite);
  });
});

test("unexpected storage failures map to a typed safe 500 without leaking internals", async () => {
  await withServer(false, async ({ baseUrl, root }) => {
    writeFileSync(join(root, "ledger.jsonl"), "{not-json}\n", "utf8");
    const response = await fetch(`${baseUrl}/api/status`);
    assert.equal(response.status, 500);
    const body = await responseJson(response);
    assert.deepEqual(body, { error: "Internal server error" });
    assert.equal(JSON.stringify(body).includes(root), false);
    assert.equal(JSON.stringify(body).includes("line 1"), false);
  });
});
