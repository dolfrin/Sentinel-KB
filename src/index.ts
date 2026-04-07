#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { audit, formatReport } from "./scanner.js";
import { allRules, Severity } from "./rules.js";

const server = new McpServer({
  name: "messenger-security-audit",
  version: "0.1.0",
});

// ─── Tool: Full audit ───────────────────────────────────────────

server.tool(
  "audit",
  "Run a full messenger security audit on a project directory. Scans for E2E encryption issues, WebRTC/P2P vulnerabilities, messenger-specific flaws, Android security, and Rust backend problems.",
  {
    projectPath: z.string().describe("Absolute path to the project root directory"),
    categories: z
      .array(z.string())
      .optional()
      .describe("Filter by categories: 'E2E Encryption', 'WebRTC/P2P', 'Messenger', 'Android', 'Backend'"),
    severity: z
      .array(z.enum(["critical", "high", "medium", "low", "info"]))
      .optional()
      .describe("Filter by minimum severity levels to include"),
  },
  async ({ projectPath, categories, severity }) => {
    try {
      const report = audit(projectPath, {
        categories: categories as string[] | undefined,
        severity: severity as Severity[] | undefined,
      });
      const text = formatReport(report);
      return {
        content: [
          { type: "text", text },
          { type: "text", text: "\n\nJSON Report:\n" + JSON.stringify(report, null, 2) },
        ],
      };
    } catch (err: any) {
      return { content: [{ type: "text", text: `Audit error: ${err.message}` }], isError: true };
    }
  }
);

// ─── Tool: List rules ───────────────────────────────────────────

server.tool(
  "list-rules",
  "List all available security audit rules with their IDs, categories, and severity levels.",
  {
    category: z.string().optional().describe("Filter by category name"),
  },
  async ({ category }) => {
    let rules = allRules;
    if (category) {
      rules = rules.filter((r) => r.category.toLowerCase().includes(category.toLowerCase()));
    }

    const lines: string[] = [];
    lines.push(`Total rules: ${rules.length}\n`);

    const byCategory: Record<string, typeof rules> = {};
    for (const r of rules) {
      if (!byCategory[r.category]) byCategory[r.category] = [];
      byCategory[r.category].push(r);
    }

    for (const [cat, catRules] of Object.entries(byCategory)) {
      lines.push(`── ${cat} (${catRules.length}) ──`);
      for (const r of catRules) {
        const icon =
          r.severity === "critical" ? "🔴" : r.severity === "high" ? "🟠" : r.severity === "medium" ? "🟡" : "🔵";
        lines.push(`  ${icon} ${r.id}: ${r.name}`);
        lines.push(`     ${r.description}`);
      }
      lines.push("");
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

// ─── Tool: Scan single file ────────────────────────────────────

server.tool(
  "scan-file",
  "Scan a single file against all messenger security rules.",
  {
    filePath: z.string().describe("Absolute path to the file to scan"),
  },
  async ({ filePath }) => {
    try {
      const path = await import("path");
      const dir = path.dirname(filePath);
      const report = audit(dir, {});
      const fileFindings = report.findings.filter(
        (f) => f.file === path.basename(filePath) || filePath.endsWith(f.file)
      );

      if (fileFindings.length === 0) {
        return { content: [{ type: "text", text: `✅ No findings in ${filePath}` }] };
      }

      const lines: string[] = [`Findings in ${filePath}:\n`];
      for (const f of fileFindings) {
        const icon =
          f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : "🔵";
        lines.push(`${icon} [${f.ruleId}] ${f.ruleName} (line ${f.line})`);
        lines.push(`   ${f.message}`);
        if (f.snippet) lines.push(`   > ${f.snippet}`);
        lines.push("");
      }

      return { content: [{ type: "text", text: lines.join("\n") }] };
    } catch (err: any) {
      return { content: [{ type: "text", text: `Scan error: ${err.message}` }], isError: true };
    }
  }
);

// ─── Start server ───────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
