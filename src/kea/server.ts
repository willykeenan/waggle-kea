import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { URL } from "node:url";
import { createFixtureFileKea } from "./factory.js";
import { createFixtureMessage } from "./fixtures.js";
import { runKeaEvaluation } from "./evaluation.js";
import { renderKeaViewerHtml } from "./viewer.js";

export interface KeaServerOptions {
  root: string;
  host?: string;
  port?: number;
  allowFixtureWrites?: boolean;
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}

function readJson(req: IncomingMessage, maxBytes = 1_000_000): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error("Kea fixture body exceeds 1 MB"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8") || "{}";
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          throw new Error("JSON object required");
        }
        resolve(parsed as Record<string, unknown>);
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

export function createKeaServer(options: KeaServerOptions) {
  const { service, registry } = createFixtureFileKea(options.root);
  const allowFixtureWrites = options.allowFixtureWrites === true;
  return createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);
    try {
      if (req.method === "GET" && url.pathname === "/") {
        const body = renderKeaViewerHtml();
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-length": Buffer.byteLength(body),
          "cache-control": "no-store",
          "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
          "x-content-type-options": "nosniff",
        });
        res.end(body);
        return;
      }
      if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/api/status")) {
        sendJson(res, 200, service.status());
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/registry") {
        sendJson(res, 200, { manifests: registry.list() });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/messages") {
        const limit = Number(url.searchParams.get("limit") || "100");
        sendJson(res, 200, { messages: service.listMessages(limit) });
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/replay/")) {
        const id = decodeURIComponent(url.pathname.slice("/api/replay/".length));
        sendJson(res, 200, service.replay(id));
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/evaluate") {
        sendJson(res, 200, runKeaEvaluation());
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/fixtures/interpret") {
        if (!allowFixtureWrites) {
          sendJson(res, 403, { error: "Fixture writes are disabled; restart with explicit --allow-fixtures" });
          return;
        }
        const body = await readJson(req);
        const payload = body.payload;
        if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
          sendJson(res, 400, { error: "payload must be a sanitized JSON object" });
          return;
        }
        const message = createFixtureMessage({
          messageId: typeof body.messageId === "string" ? body.messageId : undefined,
          missionId: typeof body.missionId === "string" ? body.missionId : undefined,
          workNodeId: typeof body.workNodeId === "string" ? body.workNodeId : undefined,
          payload: payload as Record<string, unknown>,
        });
        sendJson(res, 201, service.ingest(message));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/fixtures/correct") {
        if (!allowFixtureWrites) {
          sendJson(res, 403, { error: "Fixture writes are disabled; restart with explicit --allow-fixtures" });
          return;
        }
        const body = await readJson(req);
        const correction = service.correct({
          interpretationId: String(body.interpretationId || ""),
          actorId: String(body.actorId || ""),
          humanGloss: String(body.humanGloss || ""),
          reason: String(body.reason || ""),
        });
        sendJson(res, 201, correction);
        return;
      }
      sendJson(res, 404, { error: "Not found" });
    } catch (error) {
      sendJson(res, 400, { error: error instanceof Error ? error.message : String(error) });
    }
  });
}

export async function startKeaServer(options: KeaServerOptions): Promise<{
  host: string;
  port: number;
  close: () => Promise<void>;
}> {
  const host = options.host || "127.0.0.1";
  const requestedPort = options.port ?? 7462;
  const server = createKeaServer(options);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(requestedPort, host, () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : requestedPort;
  return {
    host,
    port,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      ),
  };
}
