const SEVERITY_LABELS = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO"
};

export function formatCliSummary(report) {
  const lines = [
    `MCP Audit Kit: ${report.score}/100 (${report.riskLevel})`,
    report.summary.headline,
    "",
    `Audited: ${report.summary.auditedTools} tools, ${report.summary.auditedServers} server configs`,
    `Findings: ${report.summary.totalFindings} total | critical ${report.counts.critical} | high ${report.counts.high} | medium ${report.counts.medium} | low ${report.counts.low}`,
    ""
  ];

  for (const finding of report.findings.slice(0, 12)) {
    const target = finding.targetName ? ` [${finding.targetType}:${finding.targetName}]` : "";
    lines.push(`- ${SEVERITY_LABELS[finding.severity]}${target} ${finding.title}`);
    lines.push(`  ${finding.recommendation}`);
  }

  if (report.findings.length > 12) {
    lines.push(`- ${report.findings.length - 12} more findings omitted. Use --json or --markdown for the full report.`);
  }

  return `${lines.join("\n")}\n`;
}

export function formatMarkdownReport(report) {
  const rows = report.findings.map((finding) => [
    finding.severity.toUpperCase(),
    finding.targetType ?? "",
    finding.targetName ?? "",
    finding.category,
    finding.title.replaceAll("|", "\\|"),
    finding.recommendation.replaceAll("|", "\\|")
  ]);

  return [
    "# MCP Audit Report",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    `Score: **${report.score}/100**`,
    `Risk level: **${report.riskLevel}**`,
    "",
    report.summary.headline,
    "",
    "## Findings",
    "",
    "| Severity | Target type | Target | Category | Finding | Recommendation |",
    "| --- | --- | --- | --- | --- | --- |",
    ...rows.map((row) => `| ${row.join(" | ")} |`),
    "",
    "## Suggested Policy",
    "",
    `- Default mode: ${report.policy.defaultMode}`,
    `- Require confirmation for: ${report.policy.requireConfirmationFor.join(", ") || "none"}`,
    `- Allow without confirmation: ${report.policy.allowWithoutConfirmation.join(", ") || "none"}`,
    `- Server isolation: ${report.policy.serverIsolation}`,
    `- Logging: ${report.policy.logging}`,
    "",
    "## Recommendations",
    "",
    ...report.recommendations.map((item) => `- ${item}`),
    ""
  ].join("\n");
}
