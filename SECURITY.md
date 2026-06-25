# Security Policy

MCP Audit Kit is a local static analyzer. It does not execute audited tools, launch MCP servers, call external APIs, or install packages.

## Reporting issues

Please open a private security advisory or contact the maintainer before publishing a vulnerability that could affect users.

Include:

- A minimal manifest or config that demonstrates the issue.
- Expected behavior.
- Actual behavior.
- Suggested severity.

## Scope

In scope:

- Incorrect handling of malicious JSON input.
- Path traversal in the local server.
- Cross-site scripting in rendered findings.
- CLI behavior that could execute untrusted input.

Out of scope:

- A risky MCP server that the scanner correctly reports as risky.
- Missing heuristics that are already listed on the roadmap.
