#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { auditManifest } from "../src/auditor.mjs";
import { formatCliSummary, formatMarkdownReport } from "../src/report.mjs";

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  printHelp();
  process.exit(0);
}

const jsonMode = args.includes("--json");
const markdownMode = args.includes("--markdown");
const failOn = readFlag("--fail-on");
const file = args.find((arg) => !arg.startsWith("--") && !["critical", "high", "medium", "low"].includes(arg));

try {
  const input = file ? await readFile(file, "utf8") : await readStdin();
  const report = auditManifest(input);

  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else if (markdownMode) {
    process.stdout.write(formatMarkdownReport(report));
  } else {
    process.stdout.write(formatCliSummary(report));
  }

  process.exitCode = failOn && shouldFail(report, failOn) ? 1 : 0;
} catch (error) {
  process.stderr.write(`mcp-audit-kit: ${error.message}\n`);
  process.exitCode = 2;
}

function readFlag(name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function shouldFail(report, threshold) {
  const order = ["info", "low", "medium", "high", "critical"];
  const normalized = order.includes(threshold) ? threshold : "critical";
  const thresholdIndex = order.indexOf(normalized);
  return report.findings.some((finding) => order.indexOf(finding.severity) >= thresholdIndex);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("error", reject);
    process.stdin.on("end", () => resolve(data));
    if (process.stdin.isTTY) {
      resolve("");
    }
  });
}

function printHelp() {
  process.stdout.write(`MCP Audit Kit

Usage:
  node bin/mcp-audit-kit.mjs <manifest.json> [--json|--markdown] [--fail-on high]
  cat manifest.json | node bin/mcp-audit-kit.mjs --markdown

Input shapes:
  - MCP tools/list response: { "result": { "tools": [...] } }
  - Plain tools array: [ { "name": "...", "inputSchema": {...} } ]
  - Client config: { "mcpServers": { "name": { "command": "...", "args": [] } } }
`);
}
