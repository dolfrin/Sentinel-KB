#!/usr/bin/env node

// CLI: sentinel-kb scan|ai|stats|search|migrate|update

import { audit, formatReport } from "./scanner.js";
import { aiScan, formatAIReport } from "./ai-scanner.js";
import { getDB, closeDB } from "./db.js";

const args = process.argv.slice(2);
const command = args[0];

function usage() {
  console.log(`
  sentinel-kb \u2014 AI-powered security vulnerability scanner

  Usage:
    sentinel-kb scan <path> [--severity critical|high|medium|low] [--category <cat>] [--json]
    sentinel-kb ai <path> [--model sonnet|opus|haiku] [--max-batches <n>] [--json]
    sentinel-kb stats
    sentinel-kb search <query>
    sentinel-kb migrate
    sentinel-kb update [--regex] [--ai-model <model>] [--concurrency <n>]

  Commands:
    scan      Static security scan (free, fast, offline)
    ai        AI-powered deep scan with KB context
    stats     Knowledge base statistics
    search    Full-text search the vulnerability KB
    migrate   Import legacy JSON data to SQLite
    update    Update knowledge base from audit sources
`);
}

async function main() {
  if (!command || command === "--help" || command === "-h") {
    usage();
    process.exit(0);
  }

  if (command === "update") {
    const { execFileSync } = await import("child_process");
    const cwd = new URL(".", import.meta.url).pathname;
    execFileSync("npx", ["tsx", "src/update.ts", ...args.slice(1)], { stdio: "inherit", cwd });
    return;
  }

  if (command === "stats") {
    const db = getDB();
    const stats = db.getStats();

    console.log(`\n\u2550\u2550\u2550 Knowledge Base Statistics \u2550\u2550\u2550\n`);
    console.log(`  Findings:   ${stats.total_findings}`);
    console.log(`  Reports:    ${stats.total_reports}`);
    console.log(`  Firms:      ${stats.total_firms}`);
    console.log(`  Canonical:  ${stats.canonical_count}`);

    console.log("\n  Severity:");
    const sevOrder = ["critical", "high", "medium", "low", "info"];
    for (const sev of sevOrder) {
      const n = stats.by_severity[sev] || 0;
      const bar = "\u2588".repeat(Math.min(Math.round(n / 20), 50));
      console.log(`    ${sev.padEnd(9)} ${String(n).padStart(5)} ${bar}`);
    }

    console.log("\n  Models:");
    for (const [model, data] of Object.entries(stats.by_model)) {
      console.log(`    ${model.padEnd(8)} ${data.reports} reports, ${data.findings} findings, $${data.cost_usd.toFixed(3)}`);
    }

    console.log("\n  Top categories:");
    for (const [cat, n] of Object.entries(stats.by_category).slice(0, 15)) {
      const bar = "\u2588".repeat(Math.min(Math.round(n / 10), 40));
      console.log(`    ${cat.padEnd(22)} ${String(n).padStart(5)} ${bar}`);
    }

    console.log("\n  Top firms:");
    for (const [firm, n] of Object.entries(stats.by_firm).slice(0, 15)) {
      console.log(`    ${firm.padEnd(25)} ${n}`);
    }

    if (args.includes("--json")) {
      console.log("\n" + JSON.stringify(stats, null, 2));
    }

    closeDB();
    return;
  }

  if (command === "search") {
    const query = args.slice(1).filter((a) => !a.startsWith("--")).join(" ");
    if (!query) {
      console.error("Usage: sentinel-kb search <query>");
      process.exit(1);
    }

    const db = getDB();
    const limitIdx = args.indexOf("--limit");
    const limit = limitIdx >= 0 ? parseInt(args[limitIdx + 1]) : 25;

    const results = db.searchFindings(query, limit);

    if (args.includes("--json")) {
      console.log(JSON.stringify(db.toExtractedFindings(results), null, 2));
    } else {
      console.log(`\n  Search: "${query}" \u2014 ${results.length} results\n`);
      for (const r of results) {
        const sev = r.severity.toUpperCase().padEnd(8);
        console.log(`  [${sev}] ${r.title}`);
        console.log(`           ${r.firm} \u2192 ${r.target} | ${r.category}${r.cwe ? ` | ${r.cwe}` : ""}`);
        if (r.description) console.log(`           ${r.description.substring(0, 120)}`);
        console.log();
      }
    }

    closeDB();
    return;
  }

  if (command === "migrate") {
    const { execFileSync } = await import("child_process");
    const cwd = new URL(".", import.meta.url).pathname;
    execFileSync("npx", ["tsx", "src/update.ts", "--migrate"], { stdio: "inherit", cwd });
    return;
  }

  const projectPath = args[1] || process.cwd();
  const useJson = args.includes("--json");
  const modelFlag = args.indexOf("--model");
  const modelMap: Record<string, string> = {
    sonnet: "claude-sonnet-4-20250514",
    opus: "claude-opus-4-20250514",
    haiku: "claude-haiku-4-5-20251001",
  };
  const modelName = modelFlag >= 0 ? (args[modelFlag + 1] || "sonnet") : "sonnet";
  const model = modelMap[modelName] || modelName;

  const maxBatchFlag = args.indexOf("--max-batches");
  const maxBatches = maxBatchFlag >= 0 ? parseInt(args[maxBatchFlag + 1]) : 20;

  if (command === "scan") {
    console.log(`\nStatic scan: ${projectPath}\n`);
    const report = audit(projectPath);

    if (useJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatReport(report));
    }

    process.exit(report.summary.critical > 0 ? 2 : report.summary.high > 0 ? 1 : 0);
  }

  if (command === "ai") {
    console.log(`\n\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550`);
    console.log(`  AI SECURITY AUDIT`);
    console.log(`  Model: ${model}`);
    console.log(`\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n`);

    const report = await aiScan(projectPath, { model, maxBatches });

    if (useJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatAIReport(report));
    }

    closeDB();
    process.exit(report.summary.critical > 0 ? 2 : report.summary.high > 0 ? 1 : 0);
  }

  console.error(`Unknown command: ${command}`);
  usage();
  process.exit(1);
}

main().catch((err) => {
  closeDB();
  console.error("Error:", err.message);
  process.exit(1);
});
