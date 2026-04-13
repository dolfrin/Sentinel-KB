// AI-powered security scanner
// Uses knowledge base (15800+ real audit findings) + Claude to analyze code
// Not regex — AI understands logic, data flow, and real vulnerability patterns

import * as fs from "fs";
import * as path from "path";
import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import { ExtractedFinding } from "./extractor.js";
import { getDB } from "./db.js";
import { gateFindings, GateConfig, GatedResult } from "./gate.js";

/** Zod schema for validating AI-returned findings */
const AIScanFindingSchema = z.object({
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  title: z.string().min(1),
  description: z.string().min(1),
  file: z.string().min(1),
  line: z.number().int().positive().optional(),
  category: z.string().min(1),
  recommendation: z.string().default(""),
  confidence: z.enum(["high", "medium", "low"]),
  relatedAuditFindings: z.array(z.string()).optional(),
});

interface BatchResult {
  findings: AIScanFinding[];
  warning?: string;
}

export interface AIScanFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  file: string;
  line?: number;
  category: string;
  recommendation: string;
  confidence: "high" | "medium" | "low";
  relatedAuditFindings?: string[]; // IDs of related knowledge base findings
}

export interface AIScanReport {
  timestamp: string;
  projectPath: string;
  filesScanned: number;
  findings: AIScanFinding[];
  errors: string[];
  summary: { critical: number; high: number; medium: number; low: number; info: number };
  knowledgeBaseSize: number;
  model: string;
  gate?: GatedResult<AIScanFinding>;
}

/** Detect project type and languages from file extensions */
function detectProjectType(files: string[]): string[] {
  const types = new Set<string>();
  for (const f of files) {
    const ext = path.extname(f).toLowerCase();
    if ([".kt", ".java"].includes(ext)) types.add("android");
    if ([".swift", ".m"].includes(ext)) types.add("ios");
    if ([".rs"].includes(ext)) types.add("rust");
    if ([".go"].includes(ext)) types.add("go");
    if ([".ts", ".js"].includes(ext)) types.add("typescript");
    if ([".py"].includes(ext)) types.add("python");
    if ([".c", ".cpp", ".h"].includes(ext)) types.add("c/c++");
    if ([".sol"].includes(ext)) types.add("solidity");
    if ([".rb"].includes(ext)) types.add("ruby");
    if ([".php"].includes(ext)) types.add("php");
    if (f.includes("Dockerfile") || f.endsWith(".yml") || f.endsWith(".yaml")) types.add("infrastructure");
    if (f.endsWith("AndroidManifest.xml")) types.add("android");
    if (f.endsWith("Cargo.toml")) types.add("rust");
  }
  return [...types];
}

/** Format knowledge base findings as context for AI */
function formatKBContext(findings: ExtractedFinding[]): string {
  const byCat: Record<string, ExtractedFinding[]> = {};
  for (const f of findings) {
    if (!byCat[f.category]) byCat[f.category] = [];
    byCat[f.category].push(f);
  }

  const lines: string[] = [];
  for (const [cat, catFindings] of Object.entries(byCat)) {
    lines.push(`\n## ${cat}`);
    for (const f of catFindings.slice(0, 15)) {
      lines.push(`- [${f.severity.toUpperCase()}] ${f.title} (${f.firm} → ${f.target})${f.cwe ? ` [${f.cwe}]` : ""}`);
    }
  }
  return lines.join("\n");
}

/** Recursively collect source files */
function collectSourceFiles(dir: string): string[] {
  const results: string[] = [];
  const skipDirs = new Set(["node_modules", ".git", "build", "target", ".gradle", ".idea", "dist", ".cxx", "__pycache__", "vendor", ".next"]);
  const sourceExts = new Set([".kt", ".java", ".rs", ".go", ".ts", ".js", ".py", ".c", ".cpp", ".h", ".swift", ".m", ".sol", ".rb", ".php", ".yaml", ".yml", ".toml", ".xml"]);

  function walk(currentDir: string) {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(currentDir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) walk(path.join(currentDir, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (sourceExts.has(ext) || entry.name === "Dockerfile" || entry.name === "AndroidManifest.xml") {
          results.push(path.join(currentDir, entry.name));
        }
      }
    }
  }

  walk(dir);
  return results;
}

/** Group files into batches for efficient AI analysis */
function groupFiles(files: string[], projectDir: string, maxCharsPerBatch: number = 30000): string[][] {
  const batches: string[][] = [];
  let currentBatch: string[] = [];
  let currentSize = 0;

  for (const file of files) {
    try {
      const stats = fs.statSync(file);
      if (stats.size > 100000) continue; // Skip very large files
      if (stats.size === 0) continue;

      if (currentSize + stats.size > maxCharsPerBatch && currentBatch.length > 0) {
        batches.push(currentBatch);
        currentBatch = [];
        currentSize = 0;
      }
      currentBatch.push(file);
      currentSize += stats.size;
    } catch { continue; }
  }

  if (currentBatch.length > 0) batches.push(currentBatch);
  return batches;
}

/** Analyze a batch of files with Claude */
async function analyzeBatch(
  client: Anthropic,
  files: string[],
  projectDir: string,
  kbContext: string,
  model: string,
): Promise<BatchResult> {
  // Read file contents
  const fileContents: string[] = [];
  for (const file of files) {
    try {
      const content = fs.readFileSync(file, "utf-8");
      const relPath = path.relative(projectDir, file);
      fileContents.push(`\n### File: ${relPath}\n\`\`\`\n${content.substring(0, 15000)}\n\`\`\``);
    } catch { continue; }
  }

  if (fileContents.length === 0) return { findings: [] };

  const systemPrompt = `You are a world-class security auditor. You have access to a knowledge base of ${kbContext.split("\n").length} real vulnerability findings extracted from professional security audits by firms like Trail of Bits, Cure53, NCC Group, and others.

Your task: analyze the provided source code and find REAL security vulnerabilities across any technology stack. Use the knowledge base patterns as guidance for what real vulnerabilities look like in production code.

RULES:
- Only report REAL vulnerabilities you are confident about (high or medium confidence)
- Do NOT report style issues, missing comments, or theoretical concerns
- Each finding must have a specific file and line number (or line range)
- Focus on: crypto misuse, auth bypass, injection, memory safety, privilege escalation, key management, data leaks, insecure deserialization, supply chain issues, config weaknesses
- If the code looks secure, say so — do not fabricate findings

Respond ONLY with valid JSON array. Each finding:
{
  "severity": "critical|high|medium|low|info",
  "title": "Short title",
  "description": "What the vulnerability is and why it matters",
  "file": "relative/path/to/file.ext",
  "line": 42,
  "category": "Cryptography|Authentication|Memory Safety|Input Validation|Key Management|Data Storage|Server Security|Mobile Security|Configuration|Information Disclosure|Access Control|Dependency Security",
  "recommendation": "How to fix it",
  "confidence": "high|medium|low"
}

If no real vulnerabilities found, respond with: []`;

  const userMessage = `## Knowledge Base — Real Vulnerability Patterns
${kbContext}

## Source Code to Audit
${fileContents.join("\n")}

Analyze the code above. Find real security vulnerabilities based on patterns from the knowledge base. Return JSON array only.`;

  const response = await client.messages.create({
    model,
    max_tokens: 8192,
    system: systemPrompt,
    messages: [{ role: "user", content: userMessage }],
  });

  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  // Extract JSON from response (may be wrapped in ```json blocks)
  const jsonMatch = text.match(/\[[\s\S]*\]/);
  if (!jsonMatch) {
    // Non-JSON reply (prose, apology, etc.) — flag as incomplete so it surfaces in errors[]
    if (text.trim().length > 0) {
      return { findings: [], warning: "model returned non-JSON response (no findings array found)" };
    }
    return { findings: [] };
  }

  let rawArray: unknown[];
  try {
    const parsed = JSON.parse(jsonMatch[0]);
    if (!Array.isArray(parsed)) return { findings: [] };
    rawArray = parsed;
  } catch {
    throw new Error("JSON parse error");
  }

  // Validate each element against the zod schema
  const validated: AIScanFinding[] = [];
  let dropped = 0;
  for (const item of rawArray) {
    const result = AIScanFindingSchema.safeParse(item);
    if (result.success) {
      validated.push(result.data as AIScanFinding);
    } else {
      dropped++;
    }
  }

  // Filter to only high/medium confidence
  const findings = validated.filter((f) => f.confidence === "high" || f.confidence === "medium");
  const warning = dropped > 0
    ? `${dropped}/${rawArray.length} findings dropped (invalid schema)`
    : undefined;
  return { findings, warning };
}

/** Run full AI-powered security scan */
export async function aiScan(
  projectDir: string,
  options?: {
    model?: string;
    maxBatches?: number;
    apiKey?: string;
    gateConfig?: GateConfig;
  }
): Promise<AIScanReport> {
  const model = options?.model || "claude-sonnet-4-20250514";
  const maxBatches = options?.maxBatches || 20;

  // Init Anthropic client
  const client = new Anthropic({
    apiKey: options?.apiKey || process.env.ANTHROPIC_API_KEY,
  });

  // Load knowledge base from SQLite
  const db = getDB();
  const stats = db.getStats();
  console.log(`  Knowledge base: ${stats.total_findings} findings from ${stats.total_firms} firms`);

  // Collect and analyze files
  const files = collectSourceFiles(projectDir);
  const projectTypes = detectProjectType(files);
  console.log(`  Project: ${projectTypes.join(", ")} (${files.length} source files)`);

  // Select relevant KB findings from DB
  const categoryMap: Record<string, string[]> = {
    "android": ["Mobile Security", "Key Management", "Authentication", "Data Storage", "Cryptography"],
    "ios": ["Mobile Security", "Key Management", "Authentication", "Data Storage", "Cryptography"],
    "rust": ["Memory Safety", "Cryptography", "Server Security", "Authentication"],
    "go": ["Memory Safety", "Server Security", "Authentication", "Cryptography"],
    "typescript": ["Input Validation", "Authentication", "Server Security", "Cryptography"],
    "python": ["Input Validation", "Authentication", "Server Security", "Cryptography"],
    "c/c++": ["Memory Safety", "Cryptography", "Server Security", "Input Validation"],
    "solidity": ["Smart Contracts", "Cryptography", "Authentication"],
    "infrastructure": ["Configuration", "Server Security", "Authentication"],
  };

  const relevantCategories = new Set(["Cryptography", "Authentication", "Information Disclosure", "General"]);
  for (const ptype of projectTypes) {
    for (const c of categoryMap[ptype] || []) relevantCategories.add(c);
  }

  const relevantRows = db.getRelevantFindingsByCategories([...relevantCategories], 20);
  const relevantKB = db.toExtractedFindings(relevantRows);
  const kbContext = formatKBContext(relevantKB);
  console.log(`  Using ${relevantKB.length} relevant KB findings as context`);

  // Group files into batches
  const batches = groupFiles(files, projectDir);
  const batchesToProcess = batches.slice(0, maxBatches);
  console.log(`  Scanning ${batchesToProcess.length} batches (${files.length} files)...\n`);

  // Analyze each batch
  const allFindings: AIScanFinding[] = [];
  const allErrors: string[] = [];
  for (let i = 0; i < batchesToProcess.length; i++) {
    const batch = batchesToProcess[i];
    const relPaths = batch.map((f) => path.relative(projectDir, f));
    console.log(`  [${i + 1}/${batchesToProcess.length}] ${relPaths.join(", ").substring(0, 80)}...`);

    try {
      const result = await analyzeBatch(client, batch, projectDir, kbContext, model);
      allFindings.push(...result.findings);

      if (result.warning) {
        const warnMsg = `Batch ${i + 1}: ${result.warning}`;
        allErrors.push(warnMsg);
        console.warn(`  !! ${warnMsg}`);
      }

      if (result.findings.length > 0) {
        for (const f of result.findings) {
          const icon = f.severity === "critical" ? "!!" : f.severity === "high" ? "!" : "-";
          console.log(`    ${icon} [${f.severity.toUpperCase()}] ${f.title} (${f.file}:${f.line || "?"})`);
        }
      }
    } catch (err: any) {
      const errorMsg = `Batch ${i + 1}: ${err.message || String(err)}`;
      allErrors.push(errorMsg);
      console.error(`  !! Batch ${i + 1} failed: ${err.message || String(err)}`);
    }
  }

  // Apply freemium gate if configured
  const gateResult = options?.gateConfig
    ? gateFindings(allFindings, options.gateConfig)
    : null;

  const visibleFindings = gateResult ? gateResult.visible : allFindings;

  // Build summary (from all findings, not just visible, so counts reflect reality)
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) {
    summary[f.severity]++;
  }

  return {
    timestamp: new Date().toISOString(),
    projectPath: projectDir,
    filesScanned: files.length,
    findings: visibleFindings,
    errors: allErrors,
    summary,
    knowledgeBaseSize: stats.total_findings,
    model,
    gate: gateResult ?? undefined,
  };
}

/** Format AI scan report as text */
export function formatAIReport(report: AIScanReport): string {
  const lines: string[] = [];
  const gate = report.gate;
  const totalCount = gate ? gate.totalCount : report.findings.length;

  lines.push("═══════════════════════════════════════════════════════════════");
  lines.push("  Sentinel-KB AI Security Audit");
  lines.push("  Powered by Claude + 15,800+ real audit findings");
  lines.push("═══════════════════════════════════════════════════════════════");
  lines.push(`  Project:        ${report.projectPath}`);
  lines.push(`  Date:           ${report.timestamp}`);
  lines.push(`  Files scanned:  ${report.filesScanned}`);
  lines.push(`  Model:          ${report.model}`);
  lines.push(`  Knowledge base: ${report.knowledgeBaseSize} findings from professional audits`);
  lines.push("───────────────────────────────────────────────────────────────");
  lines.push(`  CRITICAL: ${report.summary.critical}  HIGH: ${report.summary.high}  MEDIUM: ${report.summary.medium}  LOW: ${report.summary.low}  INFO: ${report.summary.info}`);
  lines.push("───────────────────────────────────────────────────────────────");

  if (report.errors.length > 0) {
    lines.push("");
    lines.push(`  \u26A0 ${report.errors.length} batch${report.errors.length === 1 ? "" : "es"} failed during scan \u2014 results may be incomplete`);
    for (const err of report.errors) {
      lines.push(`    - ${err}`);
    }
    lines.push("");
  }

  if (report.findings.length === 0 && (!gate || gate.gated.length === 0)) {
    lines.push("\n  No significant security issues found.\n");
  } else {
    // Group visible findings by category
    const byCat: Record<string, AIScanFinding[]> = {};
    for (const f of report.findings) {
      if (!byCat[f.category]) byCat[f.category] = [];
      byCat[f.category].push(f);
    }

    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    for (const [cat, findings] of Object.entries(byCat).sort((a, b) => a[0].localeCompare(b[0]))) {
      lines.push(`\n  ── ${cat} (${findings.length}) ──`);
      findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);

      for (const f of findings) {
        const sev = f.severity.toUpperCase().padEnd(8);
        lines.push(`\n  [${sev}] ${f.title}`);
        lines.push(`  File: ${f.file}${f.line ? `:${f.line}` : ""}`);
        lines.push(`  ${f.description}`);
        lines.push(`  Fix: ${f.recommendation}`);
      }
    }

    // Show gated findings as severity-only summaries
    if (gate && gate.isGated && gate.gated.length > 0) {
      lines.push("\n───────────────────────────────────────────────────────────────");
      lines.push(`  ${gate.gated.length} additional findings — upgrade to view details`);
      lines.push("───────────────────────────────────────────────────────────────");

      for (const g of gate.gated) {
        const sev = g.severity.toUpperCase().padEnd(8);
        lines.push(`  [${sev}] ${g.title}  (${g.category})`);
      }

      lines.push("");
      lines.push(`  *** ${gate.gateMessage} ***`);
    }
  }

  lines.push("\n═══════════════════════════════════════════════════════════════");
  lines.push(`  Total: ${totalCount} findings${gate && gate.isGated ? ` (${report.findings.length} shown, ${gate.gated.length} gated)` : ""}`);
  lines.push("═══════════════════════════════════════════════════════════════\n");

  return lines.join("\n");
}
