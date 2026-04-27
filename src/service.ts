// Shared service layer — business logic used by both CLI and MCP server.
// Keeps entry points thin: CLI parses args -> calls service -> formats output.
// MCP parses tool input -> calls service -> returns result.

import { audit, auditFile, formatReport } from "./scanner.js";
import { aiScan, formatAIReport } from "./ai-scanner.js";
import { aiTriageFindings, recalibrateSeverity } from "./ai-triage.js";
import { formatText, formatJSON, formatSARIF } from "./report.js";
import { getDB, closeDB } from "./db.js";
import type { AITriageVerdict } from "./ai-triage.js";
import {
  isRemoteKB,
  getStats as remoteGetStats,
  searchFindings as remoteSearchFindings,
} from "./kb-client.js";
import type { AuditReport, Finding } from "./scanner.js";
import type { AIScanReport, AIScanFinding } from "./ai-scanner.js";
import type { FindingRow, KBStats } from "./db.js";
import type { Severity } from "./rules.js";
import type { GateConfig } from "./gate.js";
import type { ExtractedFinding } from "./extractor.js";

// ─── Model name resolution ──────────────────────────────────

const MODEL_MAP: Record<string, string> = {
  sonnet: "claude-sonnet-4-20250514",
  opus: "claude-opus-4-20250514",
  haiku: "claude-haiku-4-5-20251001",
};

/**
 * Resolve a short model name ("sonnet", "opus", "haiku") to a full model ID.
 * If the name is not a known shorthand, it is returned as-is (assumed to be a full ID).
 */
export function resolveModelName(shortName: string): string {
  return MODEL_MAP[shortName] || shortName;
}

// ─── Static scan ────────────────────────────────────────────

export interface ScanOptions {
  severity?: Severity[];
  categories?: string[];
  includeAllDirs?: boolean;
  /** Run path/context triage (default: true) */
  triage?: boolean;
  /** Run Semgrep alongside regex rules (default: false) */
  semgrep?: boolean;
  /** Run AI triage (Claude judges each finding) — needs ANTHROPIC_API_KEY */
  aiTriage?: boolean;
  /** Min AI confidence to keep findings (default 60) */
  aiMinConfidence?: number;
  /** Output format: "text" | "json" | "sarif" (default: "text") */
  format?: "text" | "json" | "sarif";
  /** Attach KB precedents to each finding in the report */
  withKbPrecedents?: boolean;
  /**
   * Auto mode: pick engines automatically based on what's available.
   * - regex + triage: always
   * - semgrep: if CLI is installed
   * - ai-triage: if ANTHROPIC_API_KEY is set
   * - kb-precedents: if KB has data
   * Explicit options (semgrep, aiTriage, withKbPrecedents) override auto detection.
   */
  auto?: boolean;
}

export interface StaticScanResult {
  report: AuditReport;
  text: string;
  aiVerdicts?: AITriageVerdict[];
  aiCostUsd?: number;
}

/** Run a static regex scan and return both the structured report and formatted text. */
export async function runStaticScan(projectDir: string, options?: ScanOptions): Promise<StaticScanResult> {
  // Resolve auto mode → concrete options
  const auto = options?.auto === true;
  const useSemgrep = options?.semgrep !== undefined ? options.semgrep : auto;       // auto picks if CLI present (scanner re-checks)
  const useAiTriage = options?.aiTriage !== undefined
    ? options.aiTriage
    : (auto && Boolean(process.env.ANTHROPIC_API_KEY));
  const useKbPrecedents = options?.withKbPrecedents !== undefined
    ? options.withKbPrecedents
    : auto;

  const report = audit(projectDir, {
    severity: options?.severity,
    categories: options?.categories,
    includeAllDirs: options?.includeAllDirs,
    triage: options?.triage,
    semgrep: useSemgrep,
    auto,
  });

  let aiVerdicts: AITriageVerdict[] | undefined;
  let aiCostUsd: number | undefined;

  if (useAiTriage && report.findings.length > 0) {
    const aiResult = await aiTriageFindings(report.findings, projectDir, {
      minConfidence: options?.aiMinConfidence ?? 60,
    });
    if (aiResult.ran) {
      aiVerdicts = aiResult.verdicts;
      aiCostUsd = aiResult.costUsd;
      report.enginesUsed = [...(report.enginesUsed ?? []), "ai-triage"];

      // Replace findings with AI-kept set, recalibrated for severity
      const recalibrated = recalibrateSeverity(aiResult.kept, aiResult.verdicts);

      // Rebuild issues view from recalibrated findings (preserve grouping)
      type IssueShape = {
        ruleId: string;
        ruleName: string;
        severity: Severity;
        category: string;
        message: string;
        occurrences: Array<{ file: string; line: number; snippet: string; message: string }>;
        displayedOccurrences: Array<{ file: string; line: number; snippet: string; message: string }>;
        totalOccurrences: number;
      };
      const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
      const issueMap = new Map<string, IssueShape>();
      for (const f of recalibrated) {
        let entry = issueMap.get(f.ruleId);
        if (!entry) {
          entry = {
            ruleId: f.ruleId,
            ruleName: f.ruleName,
            severity: f.severity,
            category: f.category,
            message: f.message,
            occurrences: [],
            displayedOccurrences: [],
            totalOccurrences: 0,
          };
          issueMap.set(f.ruleId, entry);
        }
        entry.occurrences.push({ file: f.file, line: f.line, snippet: f.snippet, message: f.message });
        if (SEV_ORDER.indexOf(f.severity) < SEV_ORDER.indexOf(entry.severity)) {
          entry.severity = f.severity;
        }
      }
      const newIssues = Array.from(issueMap.values()).map((i) => ({
        ...i,
        displayedOccurrences: i.occurrences.slice(0, 3),
        totalOccurrences: i.occurrences.length,
      }));
      report.issues = newIssues;
      report.findings = recalibrated;
      report.totalIssues = newIssues.length;
      report.summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const i of newIssues) report.summary[i.severity]++;
    }
  }

  if (useKbPrecedents) {
    report.enginesUsed = [...(report.enginesUsed ?? []), "kb-precedents"];
  }

  const enrich = {
    aiVerdicts,
    withKbPrecedents: useKbPrecedents,
  };

  const format = options?.format ?? "text";
  let text: string;
  if (format === "json") text = formatJSON(report, enrich);
  else if (format === "sarif") text = formatSARIF(report, enrich);
  else text = formatText(report, enrich);

  return { report, text, aiVerdicts, aiCostUsd };
}

// ─── Single file scan ───────────────────────────────────────

/** Scan a single file for security vulnerabilities. */
export function scanFile(filePath: string, options?: { severity?: Severity[]; categories?: string[] }): Finding[] {
  return auditFile(filePath, options);
}

// ─── AI scan ────────────────────────────────────────────────

export interface AIScanOptions {
  model?: string;         // short name ("sonnet") or full ID
  maxBatches?: number;
  apiKey?: string;
  gateConfig?: GateConfig;
}

export interface AIScanResult {
  report: AIScanReport;
  text: string;
}

/** Run an AI-powered scan with KB context and return both the structured report and formatted text. */
export async function runAIScan(projectDir: string, options?: AIScanOptions): Promise<AIScanResult> {
  const model = options?.model ? resolveModelName(options.model) : undefined;
  const report = await aiScan(projectDir, {
    model,
    maxBatches: options?.maxBatches,
    apiKey: options?.apiKey,
    gateConfig: options?.gateConfig,
  });
  const text = formatAIReport(report);
  return { report, text };
}

// ─── KB search ──────────────────────────────────────────────

export interface SearchResult {
  findings: FindingRow[];
  extracted: ExtractedFinding[];
  query: string;
}

/** Search the knowledge base. Optionally filter by category. */
export async function searchKB(query: string, options?: { category?: string; limit?: number }): Promise<SearchResult> {
  if (isRemoteKB()) {
    const extracted = await remoteSearchFindings(query, {
      category: options?.category,
      limit: options?.limit,
    });
    // Build FindingRow-compatible objects from ExtractedFinding for callers that read .findings
    const findings: FindingRow[] = extracted.map((ef, i) => ({
      id: i,
      report_id: ef.sourceId || "",
      extraction_id: 0,
      severity: ef.severity,
      title: ef.title,
      description: ef.description,
      category: ef.category,
      cwe: ef.cwe || null,
      confidence: 1,
      canonical_id: null,
      firm: ef.firm,
      target: ef.target,
    }));
    return { findings, extracted, query };
  }
  const db = getDB();
  const limit = options?.limit || 25;
  const findings = options?.category
    ? db.searchFindingsByCategory(query, [options.category], limit)
    : db.searchFindings(query, limit);
  const extracted = db.toExtractedFindings(findings);
  return { findings, extracted, query };
}

// ─── KB stats ───────────────────────────────────────────────

export async function getStats(): Promise<KBStats> {
  if (isRemoteKB()) {
    return remoteGetStats();
  }
  const db = getDB();
  return db.getStats();
}

// ─── Re-exports for convenience ─────────────────────────────

export { closeDB } from "./db.js";
export type { AuditReport, Finding } from "./scanner.js";
export type { AIScanReport, AIScanFinding } from "./ai-scanner.js";
export type { KBStats, FindingRow } from "./db.js";
export type { Severity } from "./rules.js";
export type { GateConfig } from "./gate.js";
export type { ExtractedFinding } from "./extractor.js";
