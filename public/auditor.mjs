const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const SEVERITY_WEIGHT = {
  info: 0.5,
  low: 3,
  medium: 8,
  high: 18,
  critical: 30
};

const PROMPT_INJECTION_PATTERNS = [
  /ignore (all )?(previous|prior|above) (instructions|rules|messages)/i,
  /do not (tell|reveal|mention|show) (the )?(user|developer|operator)/i,
  /system prompt/i,
  /hidden instruction/i,
  /always (approve|execute|run|call)/i,
  /bypass (safety|policy|approval|confirmation)/i
];

const DESTRUCTIVE_PATTERNS = [
  /\b(delete|remove|destroy|wipe|drop|truncate|purge|erase)\b/i,
  /\b(write|overwrite|modify|mutate|patch|commit|push|merge)\b/i,
  /\b(send|email|message|sms|publish|post|tweet|transfer|payment|charge)\b/i
];

const EXECUTION_PATTERNS = [
  /\b(exec|execute|shell|terminal|bash|powershell|cmd|spawn|child_process)\b/i,
  /\b(eval|script|python -c|node -e|subprocess)\b/i
];

const DATA_EXFILTRATION_PATTERNS = [
  /\b(api[_ -]?key|token|secret|password|credential|private key)\b/i,
  /\b(upload|exfiltrate|export|download|read all files|filesystem)\b/i
];

const NETWORK_PATTERNS = [
  /\b(http|https|url|webhook|fetch|request|curl|external api|third[- ]party)\b/i
];

const BROAD_STRING_NAMES = [
  "command",
  "cmd",
  "script",
  "code",
  "query",
  "sql",
  "path",
  "file",
  "filename",
  "url",
  "uri",
  "body",
  "payload",
  "headers",
  "token",
  "secret"
];

export function auditManifest(input, options = {}) {
  const manifest = parseManifest(input);
  const tools = collectTools(manifest);
  const servers = collectMcpServers(manifest);
  const findings = [];

  for (const tool of tools) {
    findings.push(...auditTool(tool));
  }

  for (const server of servers) {
    findings.push(...auditServerConfig(server));
  }

  if (tools.length === 0 && servers.length === 0) {
    findings.push(makeFinding({
      severity: "medium",
      category: "Input shape",
      title: "No auditable tools or MCP servers found",
      message: "The document did not contain a tools array, tools/list result, or mcpServers config.",
      recommendation: "Export a tools/list response or paste a client MCP config with an mcpServers object."
    }));
  }

  const score = calculateScore(findings, tools.length, servers.length);
  const riskLevel = scoreToRiskLevel(score, findings);

  return {
    generatedAt: new Date().toISOString(),
    score,
    riskLevel,
    summary: summarize(findings, tools, servers),
    counts: countBySeverity(findings),
    tools: tools.map(summarizeTool),
    servers: servers.map(summarizeServer),
    findings: findings.sort(compareFindings),
    recommendations: buildRecommendations(findings),
    policy: buildSuggestedPolicy(findings, tools, servers)
  };
}

export function parseManifest(input) {
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) {
      throw new Error("Cannot audit an empty document.");
    }
    try {
      return JSON.parse(trimmed);
    } catch (error) {
      throw new Error(`Invalid JSON: ${error.message}`);
    }
  }

  if (input && typeof input === "object") {
    return input;
  }

  throw new Error("Expected a JSON string or object.");
}

export function collectTools(manifest) {
  if (Array.isArray(manifest)) {
    return manifest.map((tool, index) => normalizeTool(tool, `tool_${index + 1}`));
  }

  const candidates = [
    manifest?.tools,
    manifest?.result?.tools,
    manifest?.server?.tools,
    manifest?.capabilities?.tools
  ];

  const tools = candidates.find(Array.isArray) ?? [];
  return tools.map((tool, index) => normalizeTool(tool, `tool_${index + 1}`));
}

export function collectMcpServers(manifest) {
  const servers = manifest?.mcpServers;
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
    return [];
  }

  return Object.entries(servers).map(([name, config]) => ({
    name,
    command: config?.command,
    args: Array.isArray(config?.args) ? config.args : [],
    env: config?.env && typeof config.env === "object" ? config.env : {},
    raw: config ?? {}
  }));
}

function auditTool(tool) {
  const findings = [];
  const haystack = `${tool.name} ${tool.title} ${tool.description}`.trim();

  if (!tool.name || /^tool_\d+$/.test(tool.name)) {
    findings.push(toolFinding(tool, {
      severity: "low",
      category: "Metadata",
      title: "Tool is missing a stable name",
      message: "Tool names should be stable, unique, and descriptive so users can recognize risky calls.",
      recommendation: "Add a short action-oriented name such as read_issue, search_docs, or create_ticket."
    }));
  }

  if (!tool.description || tool.description.length < 20) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Metadata",
      title: "Tool description is too thin",
      message: "Agents depend on tool descriptions to decide when a tool is appropriate.",
      recommendation: "Describe what the tool does, what data it can access, and when it should not be used."
    }));
  }

  if (PROMPT_INJECTION_PATTERNS.some((pattern) => pattern.test(haystack))) {
    findings.push(toolFinding(tool, {
      severity: "critical",
      category: "Prompt injection",
      title: "Tool metadata contains instruction-like language",
      message: "The tool description appears to tell the model to ignore, hide, or bypass instructions.",
      evidence: excerptMatch(haystack, PROMPT_INJECTION_PATTERNS),
      recommendation: "Remove agent-directed instructions from metadata and keep behavior constraints in trusted client policy."
    }));
  }

  if (EXECUTION_PATTERNS.some((pattern) => pattern.test(haystack))) {
    findings.push(toolFinding(tool, {
      severity: "critical",
      category: "Code execution",
      title: "Tool appears able to execute commands or scripts",
      message: "Command execution tools can cross trust boundaries quickly when combined with model-generated input.",
      evidence: excerptMatch(haystack, EXECUTION_PATTERNS),
      recommendation: "Require explicit user confirmation, isolate the runtime, restrict allowed commands, and log every invocation."
    }));
  }

  if (DESTRUCTIVE_PATTERNS.some((pattern) => pattern.test(haystack))) {
    const severity = hasReadOnlyHint(tool) ? "medium" : "high";
    findings.push(toolFinding(tool, {
      severity,
      category: "Side effects",
      title: "Tool may perform destructive or external side effects",
      message: "The tool name or description suggests it can change data, publish content, or affect external systems.",
      evidence: excerptMatch(haystack, DESTRUCTIVE_PATTERNS),
      recommendation: "Set destructiveHint accurately, add a confirmation gate, and split read-only and mutating actions into separate tools."
    }));
  }

  if (DATA_EXFILTRATION_PATTERNS.some((pattern) => pattern.test(haystack))) {
    findings.push(toolFinding(tool, {
      severity: "high",
      category: "Sensitive data",
      title: "Tool metadata references sensitive data movement",
      message: "Tools that read secrets, credentials, or broad file data need strict least-privilege controls.",
      evidence: excerptMatch(haystack, DATA_EXFILTRATION_PATTERNS),
      recommendation: "Avoid exposing secrets to model-controlled tools; redact outputs and scope file/database access."
    }));
  }

  if (NETWORK_PATTERNS.some((pattern) => pattern.test(haystack))) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Network access",
      title: "Tool appears to access external network resources",
      message: "Open-world network tools can leak data or let an attacker steer the agent through remote content.",
      evidence: excerptMatch(haystack, NETWORK_PATTERNS),
      recommendation: "Use domain allowlists, request timeouts, response-size limits, and confirmation for outbound data."
    }));
  }

  findings.push(...auditSchema(tool));
  findings.push(...auditAnnotations(tool));

  return dedupeFindings(findings);
}

function auditSchema(tool) {
  const findings = [];
  const schema = tool.inputSchema;

  if (!schema || typeof schema !== "object") {
    return [
      toolFinding(tool, {
        severity: "high",
        category: "Schema",
        title: "Tool has no input schema",
        message: "Without an input schema, clients cannot validate model-generated arguments before tool execution.",
        recommendation: "Add a JSON Schema inputSchema with required fields, types, length limits, and enums where possible."
      })
    ];
  }

  if (schema.type && schema.type !== "object") {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Schema",
      title: "Input schema is not an object",
      message: `Expected an object schema for tool arguments, received "${schema.type}".`,
      recommendation: "Use an object schema with named properties so risky fields can be reviewed clearly."
    }));
  }

  const properties = schema.properties && typeof schema.properties === "object" ? schema.properties : {};
  const propertyEntries = Object.entries(properties);

  if (propertyEntries.length === 0) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Schema",
      title: "Input schema has no properties",
      message: "An empty schema makes it hard to understand and constrain the tool's input surface.",
      recommendation: "Declare each accepted argument with type, description, and validation constraints."
    }));
  }

  if (schema.additionalProperties === true || schema.additionalProperties === undefined) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Schema",
      title: "Input schema allows unknown fields",
      message: "Unknown fields make it harder to detect prompt-injected or accidental arguments.",
      recommendation: "Set additionalProperties to false after defining all accepted arguments."
    }));
  }

  if (!Array.isArray(schema.required) || schema.required.length === 0) {
    findings.push(toolFinding(tool, {
      severity: "low",
      category: "Schema",
      title: "Input schema does not require any fields",
      message: "Optional-only schemas are easy for agents to call with incomplete or ambiguous arguments.",
      recommendation: "Mark the minimum safe argument set as required."
    }));
  }

  for (const [name, property] of propertyEntries) {
    findings.push(...auditProperty(tool, name, property));
  }

  if (!tool.outputSchema) {
    findings.push(toolFinding(tool, {
      severity: "low",
      category: "Schema",
      title: "Tool has no output schema",
      message: "Output schemas help clients validate structured results before they are passed back to the model.",
      recommendation: "Add an outputSchema for structured data or document why the output is intentionally free-form."
    }));
  }

  return findings;
}

function auditProperty(tool, name, property = {}) {
  const findings = [];
  const normalizedName = name.toLowerCase();
  const isString = property.type === "string" || !property.type;
  const isDangerousName = BROAD_STRING_NAMES.some((part) => normalizedName.includes(part));
  const hasConstraint = Boolean(property.enum || property.pattern || property.format || property.maxLength || property.const);

  if (isString && isDangerousName && !hasConstraint) {
    findings.push(toolFinding(tool, {
      severity: "high",
      category: "Schema",
      title: `Broad string parameter "${name}" is unconstrained`,
      message: "Free-form command, path, URL, query, token, or payload fields are common escalation points.",
      evidence: `${name}: ${JSON.stringify(compactProperty(property))}`,
      recommendation: "Add enum, pattern, format, maxLength, or split the tool into narrower purpose-built actions."
    }));
  }

  if (isString && !property.description) {
    findings.push(toolFinding(tool, {
      severity: "low",
      category: "Schema",
      title: `Parameter "${name}" has no description`,
      message: "Argument descriptions help humans review what the model is about to send.",
      recommendation: "Add a concise description with allowed values and safety expectations."
    }));
  }

  if (property.type === "object" && property.additionalProperties !== false) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Schema",
      title: `Nested object "${name}" allows unknown fields`,
      message: "Nested free-form objects can hide injected arguments or unexpected payloads.",
      recommendation: "Define nested properties and set additionalProperties to false."
    }));
  }

  return findings;
}

function auditAnnotations(tool) {
  const findings = [];
  const annotations = tool.annotations && typeof tool.annotations === "object" ? tool.annotations : {};
  const haystack = `${tool.name} ${tool.description}`;
  const mutating = DESTRUCTIVE_PATTERNS.some((pattern) => pattern.test(haystack));
  const network = NETWORK_PATTERNS.some((pattern) => pattern.test(haystack));

  if (mutating && annotations.destructiveHint !== true) {
    findings.push(toolFinding(tool, {
      severity: "medium",
      category: "Annotations",
      title: "Mutating tool is missing destructiveHint",
      message: "Clients use annotations as UI hints when deciding whether to add friction before a call.",
      recommendation: "Set destructiveHint to true and add client-side confirmation for the action."
    }));
  }

  if (!mutating && annotations.readOnlyHint !== true) {
    findings.push(toolFinding(tool, {
      severity: "info",
      category: "Annotations",
      title: "Read-only intent is not declared",
      message: "Declaring readOnlyHint makes low-risk tools easier to trust and route automatically.",
      recommendation: "Set readOnlyHint to true for tools that cannot change external state."
    }));
  }

  if (network && annotations.openWorldHint !== true) {
    findings.push(toolFinding(tool, {
      severity: "low",
      category: "Annotations",
      title: "Network-facing tool is missing openWorldHint",
      message: "Open-world hints help clients communicate that a tool may reach external systems.",
      recommendation: "Set openWorldHint to true for tools that access network resources."
    }));
  }

  return findings;
}

function auditServerConfig(server) {
  const findings = [];
  const command = String(server.command ?? "");
  const args = server.args.map(String);
  const commandLine = [command, ...args].join(" ").trim();

  if (!command) {
    findings.push(serverFinding(server, {
      severity: "medium",
      category: "Server config",
      title: "MCP server has no command",
      message: "A client config should make the launch command explicit for review.",
      recommendation: "Pin the server command and document how it is installed."
    }));
  }

  if (/\b(cmd|powershell|bash|sh|zsh)\b/i.test(command) || /\b(-c|\/c|Invoke-Expression|iex)\b/i.test(commandLine)) {
    findings.push(serverFinding(server, {
      severity: "critical",
      category: "Server config",
      title: "Server launches through a shell",
      message: "Shell-based launch commands are easier to inject or reinterpret than direct executable calls.",
      evidence: commandLine,
      recommendation: "Launch the MCP server executable directly and avoid shell evaluation flags."
    }));
  }

  if (/\b(npx|uvx|pipx)\b/i.test(commandLine) && !/[=@]\d+\.\d+\.\d+/.test(commandLine)) {
    findings.push(serverFinding(server, {
      severity: "high",
      category: "Supply chain",
      title: "Server package is not version pinned",
      message: "Unpinned package runners can execute newly published code without a visible config change.",
      evidence: commandLine,
      recommendation: "Pin package versions and review lockfiles or checksums before rollout."
    }));
  }

  const secretEnvKeys = Object.keys(server.env).filter((key) => /(token|secret|password|api[_-]?key|credential)/i.test(key));
  if (secretEnvKeys.length > 0) {
    findings.push(serverFinding(server, {
      severity: "high",
      category: "Secrets",
      title: "Server config passes secrets through environment variables",
      message: "Secrets in client configs can be copied into screenshots, logs, or model-visible context by accident.",
      evidence: secretEnvKeys.join(", "),
      recommendation: "Use a secret manager or environment file excluded from version control, and redact values in docs."
    }));
  }

  if (args.some((arg) => /--(allow|root|dir|path|workspace)/i.test(arg)) && args.some((arg) => /[A-Z]:\\|\/Users\/|\/home\/|\/|~/.test(arg))) {
    findings.push(serverFinding(server, {
      severity: "medium",
      category: "Filesystem scope",
      title: "Server config exposes a filesystem path",
      message: "Broad filesystem roots can let unrelated private files enter the agent context.",
      evidence: commandLine,
      recommendation: "Scope file access to a dedicated workspace folder with the minimum required permissions."
    }));
  }

  return findings;
}

function normalizeTool(tool, fallbackName) {
  const raw = tool && typeof tool === "object" ? tool : {};
  return {
    name: String(raw.name ?? fallbackName),
    title: raw.title ? String(raw.title) : "",
    description: raw.description ? String(raw.description) : "",
    inputSchema: raw.inputSchema ?? raw.input_schema,
    outputSchema: raw.outputSchema ?? raw.output_schema,
    annotations: raw.annotations,
    raw
  };
}

function summarize(findings, tools, servers) {
  const counts = countBySeverity(findings);
  const highest = [...SEVERITY_ORDER].reverse().find((severity) => counts[severity] > 0) ?? "info";
  return {
    auditedTools: tools.length,
    auditedServers: servers.length,
    totalFindings: findings.length,
    highestSeverity: highest,
    headline: buildHeadline(counts, tools.length, servers.length)
  };
}

function buildHeadline(counts, toolCount, serverCount) {
  if (counts.critical > 0) {
    return "Critical review needed before connecting this tool surface to an autonomous agent.";
  }
  if (counts.high > 0) {
    return "High-risk tool behavior is present; add validation and confirmation gates first.";
  }
  if (toolCount + serverCount === 0) {
    return "No auditable MCP tools or servers were found.";
  }
  if (counts.medium > 0) {
    return "Mostly usable after tightening schema and policy controls.";
  }
  return "Looks ready for limited, monitored local use.";
}

function summarizeTool(tool) {
  const text = `${tool.name} ${tool.description}`;
  return {
    name: tool.name,
    title: tool.title || tool.name,
    tags: [
      DESTRUCTIVE_PATTERNS.some((pattern) => pattern.test(text)) ? "side-effect" : null,
      EXECUTION_PATTERNS.some((pattern) => pattern.test(text)) ? "exec" : null,
      NETWORK_PATTERNS.some((pattern) => pattern.test(text)) ? "network" : null,
      DATA_EXFILTRATION_PATTERNS.some((pattern) => pattern.test(text)) ? "sensitive-data" : null,
      hasReadOnlyHint(tool) ? "read-only" : null
    ].filter(Boolean),
    hasInputSchema: Boolean(tool.inputSchema),
    hasOutputSchema: Boolean(tool.outputSchema)
  };
}

function summarizeServer(server) {
  return {
    name: server.name,
    command: server.command ?? "",
    argCount: server.args.length,
    envKeys: Object.keys(server.env).map((key) => (/secret|token|password|api/i.test(key) ? redactKey(key) : key))
  };
}

function buildRecommendations(findings) {
  const categories = new Set(findings.filter((finding) => finding.severity !== "info").map((finding) => finding.category));
  const recommendations = [];

  if (categories.has("Prompt injection")) {
    recommendations.push("Move all behavior instructions out of tool descriptions and into trusted client policy.");
  }
  if (categories.has("Code execution")) {
    recommendations.push("Disable shell-style tools by default; require explicit per-call approval and sandboxed execution.");
  }
  if (categories.has("Schema")) {
    recommendations.push("Use strict JSON Schema: required fields, additionalProperties false, enums, patterns, and maxLength.");
  }
  if (categories.has("Side effects") || categories.has("Annotations")) {
    recommendations.push("Separate read-only tools from mutating tools and gate mutating calls with confirmation UI.");
  }
  if (categories.has("Secrets")) {
    recommendations.push("Keep secrets outside committed configs and redact them from logs, reports, and screenshots.");
  }
  if (recommendations.length === 0) {
    recommendations.push("Keep the server pinned, logged, and tested with representative tool-call fixtures.");
  }

  return recommendations;
}

function buildSuggestedPolicy(findings, tools, servers) {
  const highRiskTools = tools
    .filter((tool) => {
      const text = `${tool.name} ${tool.description}`;
      return DESTRUCTIVE_PATTERNS.some((pattern) => pattern.test(text)) ||
        EXECUTION_PATTERNS.some((pattern) => pattern.test(text)) ||
        DATA_EXFILTRATION_PATTERNS.some((pattern) => pattern.test(text));
    })
    .map((tool) => tool.name);

  return {
    defaultMode: findings.some((finding) => finding.severity === "critical") ? "manual-approval" : "monitored",
    requireConfirmationFor: [...new Set(highRiskTools)],
    allowWithoutConfirmation: tools
      .filter((tool) => hasReadOnlyHint(tool) && !highRiskTools.includes(tool.name))
      .map((tool) => tool.name),
    serverIsolation: servers.length > 0 ? "Run MCP servers with least-privilege filesystem and network access." : "No server config detected.",
    logging: "Log tool name, arguments after redaction, result size, and user confirmation decision."
  };
}

function calculateScore(findings, toolCount, serverCount) {
  const basePenalty = findings.reduce((sum, finding) => sum + SEVERITY_WEIGHT[finding.severity], 0);
  const surfaceDiscount = Math.max(0, (toolCount + serverCount - 1) * 1.5);
  return Math.max(0, Math.min(100, Math.round(100 - basePenalty + surfaceDiscount)));
}

function scoreToRiskLevel(score, findings) {
  if (findings.some((finding) => finding.severity === "critical")) return "critical";
  if (score < 55) return "high";
  if (score < 75) return "medium";
  if (score < 90) return "low";
  return "ready";
}

function countBySeverity(findings) {
  return SEVERITY_ORDER.reduce((counts, severity) => {
    counts[severity] = findings.filter((finding) => finding.severity === severity).length;
    return counts;
  }, {});
}

function makeFinding({ severity, category, title, message, recommendation, evidence, targetType, targetName }) {
  return {
    id: slug([targetType, targetName, category, title].filter(Boolean).join(" ")),
    severity,
    category,
    title,
    message,
    recommendation,
    evidence,
    targetType,
    targetName
  };
}

function toolFinding(tool, finding) {
  return makeFinding({
    ...finding,
    targetType: "tool",
    targetName: tool.name
  });
}

function serverFinding(server, finding) {
  return makeFinding({
    ...finding,
    targetType: "server",
    targetName: server.name
  });
}

function compareFindings(left, right) {
  const severityDelta = SEVERITY_ORDER.indexOf(right.severity) - SEVERITY_ORDER.indexOf(left.severity);
  if (severityDelta !== 0) return severityDelta;
  return left.title.localeCompare(right.title);
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    if (seen.has(finding.id)) return false;
    seen.add(finding.id);
    return true;
  });
}

function excerptMatch(text, patterns) {
  const pattern = patterns.find((candidate) => candidate.test(text));
  if (!pattern) return undefined;
  const match = text.match(pattern);
  if (!match) return undefined;
  const index = Math.max(0, match.index - 28);
  return text.slice(index, index + 120).trim();
}

function compactProperty(property) {
  const compact = {};
  for (const key of ["type", "format", "pattern", "enum", "maxLength", "description"]) {
    if (property[key] !== undefined) compact[key] = property[key];
  }
  return compact;
}

function hasReadOnlyHint(tool) {
  return tool.annotations && tool.annotations.readOnlyHint === true;
}

function redactKey(key) {
  return key.replace(/[A-Za-z0-9]/g, "*");
}

function slug(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "")
    .slice(0, 96);
}
