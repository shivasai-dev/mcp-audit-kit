# Architecture

MCP Audit Kit is a dependency-free Node application with three surfaces over one scanner engine.

## Surfaces

- Browser UI: `public/` calls `POST /api/audit` and renders the score, severity mix, findings, policy, and inventory.
- CLI: `bin/mcp-audit-kit.mjs` reads a file or stdin and prints text, JSON, or markdown.
- API: `server.mjs` serves static assets and exposes `/api/audit`, `/api/examples`, and `/api/health`.

## Core modules

- `src/auditor.mjs` parses input shapes, collects tools/server configs, runs rule checks, scores findings, and builds a suggested policy.
- `src/report.mjs` formats reports for terminal and markdown output.

## Input shapes

The auditor accepts:

- Plain tool arrays.
- MCP `tools/list` responses with `result.tools`.
- Objects with `tools`, `server.tools`, or `capabilities.tools`.
- MCP client configs with `mcpServers`.

## Scoring

Each finding has a severity and weight:

- `critical`: 30
- `high`: 18
- `medium`: 8
- `low`: 3
- `info`: 0.5

The score starts at 100 and subtracts weighted findings. Larger tool surfaces get a small surface discount so a healthy multi-tool server is not punished only for having more tools.

## Trust boundaries

The scanner never executes commands, imports MCP servers, calls remote APIs, or resolves package names. It only inspects user-provided JSON.

That keeps the first release safe to run on unknown manifests and easy to reason about in code review.
