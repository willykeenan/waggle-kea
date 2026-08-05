import {
  createServer,
  type IncomingMessage,
  type OutgoingHttpHeaders,
  type ServerResponse,
} from "node:http";
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

type KeaHttpStatus = 200 | 201 | 400 | 403 | 404 | 405 | 409 | 413 | 500;

const SAFE_STATUS_BY_CODE = {
  "bad-request": 400,
  forbidden: 403,
  "not-found": 404,
  "method-not-allowed": 405,
  conflict: 409,
  "payload-too-large": 413,
  "internal-error": 500,
} as const satisfies Record<string, KeaHttpStatus>;

type KeaHttpErrorCode = keyof typeof SAFE_STATUS_BY_CODE;

class KeaHttpError extends Error {
  readonly status: (typeof SAFE_STATUS_BY_CODE)[KeaHttpErrorCode];

  constructor(
    readonly code: KeaHttpErrorCode,
    readonly publicMessage: string
  ) {
    super(publicMessage);
    this.name = "KeaHttpError";
    this.status = SAFE_STATUS_BY_CODE[code];
  }
}

function safeHttpError(error: unknown): KeaHttpError {
  return error instanceof KeaHttpError
    ? error
    : new KeaHttpError("internal-error", "Internal server error");
}

function sendJson(
  res: ServerResponse,
  status: KeaHttpStatus,
  value: unknown,
  headers: OutgoingHttpHeaders = {}
): void {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  res.end(body);
}

function sendError(res: ServerResponse, error: unknown): void {
  const safe = safeHttpError(error);
  sendJson(res, safe.status, { error: safe.publicMessage });
}

function sendMethodNotAllowed(res: ServerResponse, allowed: readonly string[]): void {
  sendJson(
    res,
    SAFE_STATUS_BY_CODE["method-not-allowed"],
    { error: "Method not allowed" },
    { allow: allowed.join(", ") }
  );
}

function readJson(req: IncomingMessage, maxBytes = 1_000_000): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;

    const rejectOnce = (error: KeaHttpError): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };

    const declaredLength = req.headers["content-length"];
    if (declaredLength !== undefined) {
      if (!/^\d+$/.test(declaredLength)) {
        req.resume();
        rejectOnce(new KeaHttpError("bad-request", "Invalid Content-Length header"));
        return;
      }
      const declaredBytes = Number(declaredLength);
      if (!Number.isSafeInteger(declaredBytes) || declaredBytes > maxBytes) {
        req.resume();
        rejectOnce(new KeaHttpError("payload-too-large", "Kea fixture body exceeds 1 MB"));
        return;
      }
    }

    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        chunks.length = 0;
        rejectOnce(new KeaHttpError("payload-too-large", "Kea fixture body exceeds 1 MB"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) return;
      try {
        const raw = Buffer.concat(chunks).toString("utf8") || "{}";
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          rejectOnce(new KeaHttpError("bad-request", "JSON object required"));
          return;
        }
        settled = true;
        resolve(parsed as Record<string, unknown>);
      } catch {
        rejectOnce(new KeaHttpError("bad-request", "Malformed JSON body"));
      }
    });
    req.on("error", () => {
      rejectOnce(new KeaHttpError("bad-request", "Request body could not be read"));
    });
  });
}

function parseMessageLimit(url: URL): number {
  const values = url.searchParams.getAll("limit");
  if (values.length === 0) return 100;
  const raw = values[0];
  if (values.length !== 1 || raw === undefined || !/^[1-9]\d*$/.test(raw)) {
    throw new KeaHttpError("bad-request", "limit must be one integer from 1 through 500");
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > 500) {
    throw new KeaHttpError("bad-request", "limit must be one integer from 1 through 500");
  }
  return value;
}

function allowedMethods(pathname: string): readonly string[] | null {
  if (
    pathname === "/" ||
    pathname === "/health" ||
    pathname === "/api/status" ||
    pathname === "/api/registry" ||
    pathname === "/api/messages" ||
    pathname === "/api/evaluate" ||
    pathname.startsWith("/api/replay/")
  ) {
    return ["GET"];
  }
  if (pathname === "/api/fixtures/interpret" || pathname === "/api/fixtures/correct") {
    return ["POST"];
  }
  return null;
}

function isErrorWithPrefix(error: unknown, prefix: string): boolean {
  return error instanceof Error && error.message.startsWith(prefix);
}

export function createKeaServer(options: KeaServerOptions) {
  const { service, registry } = createFixtureFileKea(options.root);
  const allowFixtureWrites = options.allowFixtureWrites === true;
  return createServer(async (req, res) => {
    try {
      let url: URL;
      try {
        url = new URL(req.url || "/", "http://127.0.0.1");
      } catch {
        throw new KeaHttpError("bad-request", "Invalid request URL");
      }

      const allowed = allowedMethods(url.pathname);
      const method = req.method || "GET";
      if (allowed && !allowed.includes(method)) {
        sendMethodNotAllowed(res, allowed);
        return;
      }

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
        const limit = parseMessageLimit(url);
        sendJson(res, 200, { messages: service.listMessages(limit) });
        return;
      }
      if (req.method === "GET" && url.pathname.startsWith("/api/replay/")) {
        let id: string;
        try {
          id = decodeURIComponent(url.pathname.slice("/api/replay/".length));
        } catch {
          throw new KeaHttpError("bad-request", "Replay ID is not valid URL encoding");
        }
        try {
          sendJson(res, 200, service.replay(id));
        } catch (error) {
          if (isErrorWithPrefix(error, "Unknown Kea message")) {
            throw new KeaHttpError("not-found", "Replay not found");
          }
          throw error;
        }
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
        try {
          sendJson(res, 201, service.ingest(message));
        } catch (error) {
          if (isErrorWithPrefix(error, `Kea message ${message.messageId} is immutable`)) {
            throw new KeaHttpError("conflict", "Fixture message ID conflicts with an existing record");
          }
          throw error;
        }
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/fixtures/correct") {
        if (!allowFixtureWrites) {
          sendJson(res, 403, { error: "Fixture writes are disabled; restart with explicit --allow-fixtures" });
          return;
        }
        const body = await readJson(req);
        try {
          const correction = service.correct({
            interpretationId: String(body.interpretationId || ""),
            actorId: String(body.actorId || ""),
            humanGloss: String(body.humanGloss || ""),
            reason: String(body.reason || ""),
          });
          sendJson(res, 201, correction);
          return;
        } catch (error) {
          if (isErrorWithPrefix(error, "Unknown Kea interpretation")) {
            throw new KeaHttpError("not-found", "Interpretation not found");
          }
          if (isErrorWithPrefix(error, "Kea correction requires")) {
            throw new KeaHttpError("bad-request", "Correction requires actor, gloss, and reason");
          }
          throw error;
        }
      }
      throw new KeaHttpError("not-found", "Not found");
    } catch (error) {
      sendError(res, error);
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
