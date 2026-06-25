# MCP Audit Kit

Local-first scanner for MCP tool manifests, agent tool configs, and tool-call risk.

MCP Audit Kit helps developers review the tools they expose to AI agents before those tools can read files, call APIs, run commands, or mutate production systems. It ships with a browser UI, CLI, API endpoint, fixtures, tests, and GitHub Actions CI without any runtime dependencies.

## Why this exists

AI agents are moving from chat into action. The Model Context Protocol gives AI apps a standard way to connect to external systems, including files, databases, APIs, and workflows. That is powerful, but it also means a small unsafe tool definition can become a large trust problem.

The 2025 Stack Overflow Developer Survey reports that 84% of respondents use or plan to use AI tools, while 46% actively distrust AI tool accuracy. MCP's own tool spec recommends input validation, human confirmation for sensitive operations, visible tool invocation UI, result validation, timeouts, and audit logging. This project turns those safety ideas into a fast local audit workflow.

## Features

- Audit MCP `tools/list` responses, plain tool arrays, and common `mcpServers` client configs.
- Flag prompt-injection language in tool descriptions.
- Detect risky side effects such as shell execution, destructive actions, network calls, and sensitive data movement.
- Review JSON Schema quality: missing schemas, broad string parameters, unknown fields, and missing output schemas.
- Generate a suggested client policy for confirmation gates, logging, and server isolation.
- Run as a no-install browser app or as a CLI for CI.

## Quick start

```bash
npm start
```

Open `http://localhost:4173`.

Run the CLI:

```bash
node bin/mcp-audit-kit.mjs fixtures/risky-mcp.json
node bin/mcp-audit-kit.mjs fixtures/safe-mcp.json --markdown
node bin/mcp-audit-kit.mjs fixtures/mcp-client-config.json --json
```

Run tests:

```bash
npm run ci
```

## Input examples

MCP `tools/list` response:

```json
{
  "result": {
    "tools": [
      {
        "name": "search_docs",
        "description": "Search a local documentation index.",
        "inputSchema": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "query": {
              "type": "string",
              "maxLength": 120
            }
          },
          "required": ["query"]
        },
        "annotations": {
          "readOnlyHint": true
        }
      }
    ]
  }
}
```

MCP client config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "C:\\Users\\shiva"]
    }
  }
}
```

## Risk model

MCP Audit Kit is intentionally heuristic. It is not a formal security scanner and it does not execute tools. It reviews the exposed interface and highlights places where a human should add stricter validation, confirmation, or isolation.

Signals include:

- Prompt-injection phrases in metadata.
- Shell, script, or command execution.
- Delete, write, publish, payment, or transfer language.
- Secret, token, password, upload, export, or filesystem language.
- Free-form `command`, `path`, `url`, `payload`, `sql`, `query`, or `script` fields.
- Missing `inputSchema`, missing `outputSchema`, permissive `additionalProperties`, and missing `required`.
- Shell-based server launch, unpinned package runners, broad filesystem roots, and secret-looking env vars.

## Roadmap

- Manifest diffing to catch tool descriptor rug pulls.
- SARIF output for GitHub code scanning.
- Ruleset profiles for local dev, enterprise, CI, and production agents.
- Package installer mode for `npx mcp-audit-kit`.
- Signed manifest policy checks.

## Project structure

```text
bin/                 CLI entrypoint
docs/                research, architecture, launch notes
fixtures/            safe/risky demo manifests
public/              browser UI
src/                 scanner and report generation
tests/               node:test coverage
server.mjs           local API + static server
```

## License

MIT
