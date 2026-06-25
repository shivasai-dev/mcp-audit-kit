import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { auditManifest, collectMcpServers, collectTools } from "../src/auditor.mjs";

const fixtures = new URL("../fixtures/", import.meta.url);

test("collects tools from a tools/list response", async () => {
  const safe = JSON.parse(await readFile(new URL("safe-mcp.json", fixtures), "utf8"));
  const tools = collectTools(safe);

  assert.equal(tools.length, 2);
  assert.equal(tools[0].name, "search_docs");
});

test("safe read-only tools score higher than risky tools", async () => {
  const safe = await readFile(new URL("safe-mcp.json", fixtures), "utf8");
  const risky = await readFile(new URL("risky-mcp.json", fixtures), "utf8");

  const safeReport = auditManifest(safe);
  const riskyReport = auditManifest(risky);

  assert.ok(safeReport.score > riskyReport.score);
  assert.equal(riskyReport.riskLevel, "critical");
});

test("detects prompt injection and shell execution in tool metadata", async () => {
  const risky = await readFile(new URL("risky-mcp.json", fixtures), "utf8");
  const report = auditManifest(risky);
  const titles = report.findings.map((finding) => finding.title);

  assert.ok(titles.includes("Tool metadata contains instruction-like language"));
  assert.ok(titles.includes("Tool appears able to execute commands or scripts"));
});

test("detects MCP client config server risks", async () => {
  const config = JSON.parse(await readFile(new URL("mcp-client-config.json", fixtures), "utf8"));
  const servers = collectMcpServers(config);
  const report = auditManifest(config);
  const categories = new Set(report.findings.map((finding) => finding.category));

  assert.equal(servers.length, 3);
  assert.ok(categories.has("Supply chain"));
  assert.ok(categories.has("Secrets"));
  assert.ok(categories.has("Server config"));
});

test("returns an input-shape finding for unrelated JSON", () => {
  const report = auditManifest({ hello: "world" });

  assert.equal(report.summary.auditedTools, 0);
  assert.equal(report.summary.auditedServers, 0);
  assert.equal(report.counts.medium, 1);
});
