# Research Notes

## Trend signal

MCP is a strong product direction because it sits at the intersection of three active developer needs: AI agents, tool calling, and trust.

- The official MCP introduction describes MCP as an open-source standard that connects AI apps to external systems such as files, databases, tools, and workflows. It also notes broad support across AI assistants and development tools: <https://modelcontextprotocol.io/docs/getting-started/intro>
- The MCP tools specification says tools are model-controlled and can be invoked automatically by language models. It recommends clear UI, human confirmation for operations, input validation, access control, rate limits, output sanitization, result validation, timeouts, and audit logging: <https://modelcontextprotocol.io/specification/2025-06-18/server/tools>
- Stack Overflow's 2025 Developer Survey reports that 84% of respondents use or plan to use AI tools, but 46% actively distrust AI tool accuracy. It also reports that 66% cite AI solutions being "almost right, but not quite" as their biggest frustration: <https://survey.stackoverflow.co/2025/ai/>

## Product wedge

Most MCP tooling helps people connect servers. MCP Audit Kit helps people decide whether a server should be trusted before they connect it to an agent.

That is a practical wedge because developers and teams can use it without changing their stack:

- Paste a `tools/list` JSON response.
- Paste a local MCP client config.
- Run a CLI in CI.
- Get a readable report that maps risks to concrete policy actions.

## Why it can earn attention

The project is useful to a broad set of developers:

- AI-agent builders who need to review tool surfaces.
- Security engineers who want an approachable preflight check.
- Open-source MCP server maintainers who want a "trust badge" workflow.
- Recruiters/interviewers who want to see full-stack product thinking, not only CRUD apps.

## Initial rule priorities

The first release focuses on high-signal checks that are easy to explain:

- Prompt-injection phrases hidden in tool metadata.
- Command execution and shell launches.
- Destructive or externally visible side effects.
- Secret and filesystem exposure.
- Missing or permissive JSON Schema.
- Unpinned package runners in local MCP configs.

## Positioning

MCP Audit Kit should not claim to prove safety. The honest promise is: "Catch obvious tool-surface risk before the model sees it."
