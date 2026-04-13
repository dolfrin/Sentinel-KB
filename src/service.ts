// Shared service layer — business logic used by both CLI and MCP server.
// Keeps entry points thin: CLI parses args -> calls service -> formats output.
// MCP parses tool input -> calls service -> returns result.

import { audit, auditFile, formatReport } from "./scanner.js";
import { aiScan, formatAIReport } from "./ai-scanner.js";
import { getDB, closeDB } from "./db.js";
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
}

export interface StaticScanResult {
  report: AuditReport;
  text: string;
}

/** Run a static regex scan and return both the structured report and formatted text. */
export function runStaticScan(projectDir: string, options?: ScanOptions): StaticScanResult {
  const report = audit(projectDir, {
    severity: options?.severity,
    categories: options?.categories,
    includeAllDirs: options?.includeAllDirs,
  });
  const text = formatReport(report);
  return { report, text };
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
export function searchKB(query: string, options?: { category?: string; limit?: number }): SearchResult {
  const db = getDB();
  const limit = options?.limit || 25;
  const findings = options?.category
    ? db.searchFindingsByCategory(query, [options.category], limit)
    : db.searchFindings(query, limit);
  const extracted = db.toExtractedFindings(findings);
  return { findings, extracted, query };
}

// ─── KB stats ───────────────────────────────────────────────

export function getStats(): KBStats {
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
