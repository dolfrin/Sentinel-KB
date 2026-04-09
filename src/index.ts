#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { audit, formatReport } from "./scanner.js";
import { allRules, Severity } from "./rules.js";
import { aiScan, formatAIReport } from "./ai-scanner.js";
import { getDB } from "./db.js";

const server = new McpServer({
  name: "sentinel-kb",
  version: "0.1.0",
});

// ─── Tool: Full audit ───────────────────────────────────────────

server.tool(
  "audit",
  "Run a comprehensive static security scan on a codebase. Scans for vulnerabilities across OWASP categories including injection, XSS, cryptography, authentication, secrets exposure, and more.",
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
  "List all available static security scan rules with their severity, category, and detection patterns.",
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
  "Scan a single file for security vulnerabilities using static analysis rules.",
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

// ─── Tool: AI-powered audit ────────────────────────────────────

server.tool(
  "ai-audit",
  "Run an AI-powered security audit using Claude with knowledge base context from 2000+ real audit findings. Provides deep analysis of vulnerabilities with fix recommendations.",
  {
    projectPath: z.string().describe("Absolute path to the project root directory"),
    model: z
      .enum(["sonnet", "opus", "haiku"])
      .optional()
      .describe("Claude model to use (default: sonnet)"),
    maxBatches: z.number().optional().describe("Max file batches to analyze (default: 20)"),
  },
  async ({ projectPath, model, maxBatches }) => {
    try {
      const modelMap: Record<string, string> = {
        sonnet: "claude-sonnet-4-20250514",
        opus: "claude-opus-4-20250514",
        haiku: "claude-haiku-4-5-20251001",
      };
      const report = await aiScan(projectPath, {
        model: model ? modelMap[model] : undefined,
        maxBatches: maxBatches || undefined,
      });
      const text = formatAIReport(report);
      return {
        content: [
          { type: "text", text },
          { type: "text", text: "\n\nJSON Report:\n" + JSON.stringify(report, null, 2) },
        ],
      };
    } catch (err: any) {
      return { content: [{ type: "text", text: `AI audit error: ${err.message}` }], isError: true };
    }
  }
);

// ─── Tool: Knowledge base stats ───────────────────────────────

server.tool(
  "kb-stats",
  "Show knowledge base statistics including total findings, reports, severity breakdown, and extraction costs.",
  {},
  async () => {
    try {
      const db = getDB();
      const stats = db.getStats();

      const lines: string[] = [];
      lines.push(`Knowledge Base: ${stats.total_findings} findings from ${stats.total_reports} reports by ${stats.total_firms} firms`);
      lines.push(`Canonical patterns: ${stats.canonical_count}\n`);

      lines.push("Severity:");
      for (const sev of ["critical", "high", "medium", "low", "info"]) {
        lines.push(`  ${sev}: ${stats.by_severity[sev] || 0}`);
      }

      lines.push("\nModels:");
      for (const [model, data] of Object.entries(stats.by_model)) {
        lines.push(`  ${model}: ${data.reports} reports, ${data.findings} findings, $${data.cost_usd.toFixed(3)}`);
      }

      lines.push("\nTop categories:");
      for (const [cat, n] of Object.entries(stats.by_category).slice(0, 15)) {
        lines.push(`  ${cat}: ${n}`);
      }

      lines.push("\nTop firms:");
      for (const [firm, n] of Object.entries(stats.by_firm).slice(0, 15)) {
        lines.push(`  ${firm}: ${n}`);
      }

      return {
        content: [
          { type: "text", text: lines.join("\n") },
          { type: "text", text: "\n\nJSON:\n" + JSON.stringify(stats, null, 2) },
        ],
      };
    } catch (err: any) {
      return { content: [{ type: "text", text: `Stats error: ${err.message}` }], isError: true };
    }
  }
);

// ─── Tool: Search knowledge base ──────────────────────────────

server.tool(
  "search-kb",
  "Full-text search the vulnerability knowledge base for specific patterns, CVEs, or vulnerability types.",
  {
    query: z.string().describe("Search query — keywords, CWE IDs, vulnerability types"),
    category: z.string().optional().describe("Filter by category"),
    limit: z.number().optional().describe("Max results (default: 25)"),
  },
  async ({ query, category, limit }) => {
    try {
      const db = getDB();
      const maxResults = limit || 25;

      const results = category
        ? db.searchFindingsByCategory(query, [category], maxResults)
        : db.searchFindings(query, maxResults);

      if (results.length === 0) {
        return { content: [{ type: "text", text: `No findings matching "${query}"` }] };
      }

      const lines: string[] = [`Search: "${query}" — ${results.length} results\n`];
      for (const r of results) {
        lines.push(`[${r.severity.toUpperCase()}] ${r.title}`);
        lines.push(`  ${r.firm} → ${r.target} | ${r.category}${r.cwe ? ` | ${r.cwe}` : ""}`);
        if (r.description) lines.push(`  ${r.description.substring(0, 150)}`);
        lines.push("");
      }

      return {
        content: [
          { type: "text", text: lines.join("\n") },
          { type: "text", text: "\n\nJSON:\n" + JSON.stringify(db.toExtractedFindings(results), null, 2) },
        ],
      };
    } catch (err: any) {
      return { content: [{ type: "text", text: `Search error: ${err.message}` }], isError: true };
    }
  }
);

// ─── Start server ───────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
