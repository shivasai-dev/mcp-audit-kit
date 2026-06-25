import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { auditManifest } from "./src/auditor.mjs";

const root = fileURLToPath(new URL(".", import.meta.url));
const publicRoot = join(root, "public");
const fixturesRoot = join(root, "fixtures");
const port = Number(process.env.PORT ?? 4173);

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8"
};

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host}`);

    if (request.method === "GET" && url.pathname === "/api/health") {
      return sendJson(response, { ok: true, name: "mcp-audit-kit" });
    }

    if (request.method === "GET" && url.pathname === "/api/examples") {
      const [safe, risky, config] = await Promise.all([
        readFile(join(fixturesRoot, "safe-mcp.json"), "utf8"),
        readFile(join(fixturesRoot, "risky-mcp.json"), "utf8"),
        readFile(join(fixturesRoot, "mcp-client-config.json"), "utf8")
      ]);
      return sendJson(response, {
        examples: [
          { id: "safe", label: "Safe sample", document: JSON.parse(safe) },
          { id: "risky", label: "Risky sample", document: JSON.parse(risky) },
          { id: "config", label: "Client config", document: JSON.parse(config) }
        ]
      });
    }

    if (request.method === "POST" && url.pathname === "/api/audit") {
      const body = await readBody(request);
      const payload = JSON.parse(body || "{}");
      const report = auditManifest(payload.document ?? payload);
      return sendJson(response, report);
    }

    if (request.method !== "GET") {
      return sendText(response, 405, "Method not allowed");
    }

    const path = url.pathname === "/" ? "/index.html" : url.pathname;
    const filePath = safeJoin(publicRoot, path);
    const contents = await readFile(filePath);
    response.writeHead(200, {
      "content-type": mimeTypes[extname(filePath)] ?? "application/octet-stream"
    });
    response.end(contents);
  } catch (error) {
    if (error.code === "ENOENT") {
      return sendText(response, 404, "Not found");
    }

    const status = error instanceof SyntaxError ? 400 : 500;
    return sendJson(response, { error: error.message }, status);
  }
});

server.listen(port, () => {
  console.log(`MCP Audit Kit running at http://localhost:${port}`);
});

function safeJoin(base, requestPath) {
  const decoded = decodeURIComponent(requestPath);
  const target = normalize(join(base, decoded));
  if (!target.startsWith(base)) {
    throw Object.assign(new Error("Invalid path"), { code: "ENOENT" });
  }
  return target;
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let data = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        request.destroy(new Error("Request body too large"));
      }
    });
    request.on("end", () => resolve(data));
    request.on("error", reject);
  });
}

function sendJson(response, payload, status = 200) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function sendText(response, status, text) {
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8" });
  response.end(text);
}
