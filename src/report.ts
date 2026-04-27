// sentinel-kb-ignore-file
// Report formatters — turn an AuditReport into human-readable, JSON, or SARIF output.
//
// Design notes:
// - formatText: terminal-friendly, grouped by category, KB precedents inline.
// - formatJSON: structured, suitable for piping into jq or another tool.
// - formatSARIF: SARIF 2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/),
//   the format GitHub Code Scanning ingests natively.

import type { AuditReport, Finding, Issue } from "./scanner.js";
import type { Severity } from "./rules.js";
import type { AITriageVerdict } from "./ai-triage.js";
import { getDB } from "./db.js";

// ─── Types ─────────────────────────────────────────────────────

export interface ReportEnrichment {
  /** Optional AI verdicts to attach per finding */
  aiVerdicts?: AITriageVerdict[];
  /** Whether to look up KB precedents for each finding */
  withKbPrecedents?: boolean;
  /** Max KB precedents to attach per finding (default 2) */
  kbPrecedentLimit?: number;
}

interface KBPrecedent {
  id: number;
  firm: string;
  target: string;
  title: string;
  severity: string;
  cwe?: string;
}

// ─── KB precedent lookup ───────────────────────────────────────

function lookupKbPrecedents(finding: Finding, limit: number): KBPrecedent[] {
  try {
    const db = getDB();
    const query = `${finding.category} ${finding.message}`.replace(/[^a-zA-Z0-9 ]/g, " ").slice(0, 200);
    const rows = db.searchFindingsByCategory(query, [finding.category], limit);
    const fallback = rows.length === 0 ? db.searchFindings(query, limit) : rows;
    return fallback.slice(0, limit).map((r: any) => ({
      id: r.id,
      firm: r.firm,
      target: r.target,
      title: r.title,
      severity: r.severity,
      cwe: r.cwe,
    }));
  } catch {
    return [];
  }
}

// ─── Verdict lookup ────────────────────────────────────────────

function findVerdict(verdicts: AITriageVerdict[] | undefined, finding: Finding): AITriageVerdict | undefined {
  if (!verdicts) return undefined;
  return verdicts.find((v) => v.ruleId === finding.ruleId && v.file === finding.file && v.line === finding.line);
}

// ─── Severity styling ──────────────────────────────────────────

const SEV_ICON: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

const SEV_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

// ─── Text formatter ────────────────────────────────────────────

export function formatText(report: AuditReport, enrich?: ReportEnrichment): string {
  const lines: string[] = [];
  const issues = report.issues ?? [];
  const totalIssues = report.totalIssues ?? issues.length;
  const kbLimit = enrich?.kbPrecedentLimit ?? 2;

  // Header
  lines.push("═══════════════════════════════════════════════════════");
  lines.push("  Sentinel-KB Security Audit");
  lines.push("═══════════════════════════════════════════════════════");
  lines.push(`  Project:  ${report.projectPath}`);
  lines.push(`  Date:     ${report.timestamp}`);
  lines.push(`  Files:    ${report.totalFiles} scanned`);
  lines.push(`  Issues:   ${totalIssues} distinct`);
  lines.push(
    `  Severity: ${SEV_ICON.critical} ${report.summary.critical}  ${SEV_ICON.high} ${report.summary.high}  ${SEV_ICON.medium} ${report.summary.medium}  ${SEV_ICON.low} ${report.summary.low}  ${SEV_ICON.info} ${report.summary.info}`
  );
  if (report.triage) {
    lines.push(
      `  Triage:   -${report.triage.droppedCount} false positives, ${report.triage.downgradedCount} severity downgrades`
    );
  }
  lines.push("───────────────────────────────────────────────────────");

  if (issues.length === 0) {
    lines.push("");
    lines.push("  ✅ No findings. Clean run.");
    lines.push("");
    return lines.join("\n");
  }

  // Group issues by category
  const byCategory: Record<string, Issue[]> = {};
  for (const issue of issues) {
    (byCategory[issue.category] ??= []).push(issue);
  }

  // Categories sorted by highest severity present
  const categoriesSorted = Object.keys(byCategory).sort((a, b) => {
    const aMin = Math.min(...byCategory[a].map((i) => SEV_RANK[i.severity]));
    const bMin = Math.min(...byCategory[b].map((i) => SEV_RANK[i.severity]));
    return aMin - bMin;
  });

  for (const category of categoriesSorted) {
    const catIssues = byCategory[category];
    lines.push("");
    lines.push(`  ── ${category} (${catIssues.length}) ──`);
    lines.push("");

    for (const issue of catIssues) {
      lines.push(`  ${SEV_ICON[issue.severity]} [${issue.ruleId}] ${issue.ruleName}`);
      lines.push(`     ${issue.message}`);

      // First displayed occurrence — anchor for KB lookup + AI verdict
      const anchor = issue.displayedOccurrences[0];

      for (const occ of issue.displayedOccurrences) {
        if (occ.file !== "(project-wide)") {
          lines.push(`     ${occ.file}:${occ.line}`);
        }
        if (occ.snippet) {
          lines.push(`     > ${occ.snippet}`);
        }
      }
      if (issue.totalOccurrences > issue.displayedOccurrences.length) {
        const more = issue.totalOccurrences - issue.displayedOccurrences.length;
        lines.push(`     ... and ${more} more (${issue.totalOccurrences} total)`);
      }

      // AI verdict line
      if (anchor && enrich?.aiVerdicts) {
        const finding: Finding = {
          ruleId: issue.ruleId,
          ruleName: issue.ruleName,
          severity: issue.severity,
          category: issue.category,
          message: anchor.message,
          file: anchor.file,
          line: anchor.line,
          snippet: anchor.snippet,
        };
        const v = findVerdict(enrich.aiVerdicts, finding);
        if (v) {
          const tag = v.isReal ? "✓ Real" : "✗ FP";
          lines.push(`     AI: ${tag} (${v.confidence}%) — ${v.reasoning}`);
        }
      }

      // KB precedents
      if (anchor && enrich?.withKbPrecedents) {
        const finding: Finding = {
          ruleId: issue.ruleId,
          ruleName: issue.ruleName,
          severity: issue.severity,
          category: issue.category,
          message: anchor.message,
          file: anchor.file,
          line: anchor.line,
          snippet: anchor.snippet,
        };
        const precedents = lookupKbPrecedents(finding, kbLimit);
        if (precedents.length > 0) {
          lines.push(`     KB precedents:`);
          for (const p of precedents) {
            const cwe = p.cwe ? ` [${p.cwe}]` : "";
            lines.push(`       • ${p.firm} → ${p.target}: ${p.title}${cwe}`);
          }
        }
      }

      lines.push("");
    }
  }

  lines.push("═══════════════════════════════════════════════════════");
  return lines.join("\n");
}

// ─── JSON formatter ────────────────────────────────────────────

export function formatJSON(report: AuditReport, enrich?: ReportEnrichment): string {
  const enriched: any = {
    ...report,
    issues: (report.issues ?? []).map((issue) => {
      const anchor = issue.displayedOccurrences[0];
      const finding: Finding | null = anchor ? {
        ruleId: issue.ruleId,
        ruleName: issue.ruleName,
        severity: issue.severity,
        category: issue.category,
        message: anchor.message,
        file: anchor.file,
        line: anchor.line,
        snippet: anchor.snippet,
      } : null;

      const out: any = { ...issue };
      if (finding && enrich?.aiVerdicts) {
        const v = findVerdict(enrich.aiVerdicts, finding);
        if (v) out.aiVerdict = v;
      }
      if (finding && enrich?.withKbPrecedents) {
        out.kbPrecedents = lookupKbPrecedents(finding, enrich.kbPrecedentLimit ?? 2);
      }
      return out;
    }),
  };
  return JSON.stringify(enriched, null, 2);
}

// ─── SARIF 2.1.0 formatter ─────────────────────────────────────

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number };
    };
  }>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, any>;
}

const SEV_TO_SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function formatSARIF(report: AuditReport, enrich?: ReportEnrichment): string {
  const issues = report.issues ?? [];
  const ruleSet = new Map<string, { id: string; name: string; severity: Severity; category: string; help: string }>();
  const results: SarifResult[] = [];

  for (const issue of issues) {
    if (!ruleSet.has(issue.ruleId)) {
      ruleSet.set(issue.ruleId, {
        id: issue.ruleId,
        name: issue.ruleName,
        severity: issue.severity,
        category: issue.category,
        help: issue.message,
      });
    }
    for (const occ of issue.occurrences) {
      const result: SarifResult = {
        ruleId: issue.ruleId,
        level: SEV_TO_SARIF_LEVEL[issue.severity],
        message: { text: occ.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: occ.file },
            region: { startLine: occ.line || 1 },
          },
        }],
        partialFingerprints: {
          "primaryLocationLineHash": `${issue.ruleId}:${occ.file}:${occ.line}`,
        },
        properties: {
          severity: issue.severity,
          category: issue.category,
        },
      };

      if (enrich?.aiVerdicts) {
        const finding: Finding = {
          ruleId: issue.ruleId,
          ruleName: issue.ruleName,
          severity: issue.severity,
          category: issue.category,
          message: occ.message,
          file: occ.file,
          line: occ.line,
          snippet: occ.snippet,
        };
        const v = findVerdict(enrich.aiVerdicts, finding);
        if (v) {
          result.properties!.aiConfidence = v.confidence;
          result.properties!.aiIsReal = v.isReal;
          result.properties!.aiReasoning = v.reasoning;
        }
      }
      results.push(result);
    }
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "sentinel-kb",
          informationUri: "https://github.com/dolfrin/Sentinel-KB",
          version: "0.1.0",
          rules: Array.from(ruleSet.values()).map((r) => ({
            id: r.id,
            name: r.name,
            shortDescription: { text: r.name },
            fullDescription: { text: r.help },
            defaultConfiguration: { level: SEV_TO_SARIF_LEVEL[r.severity] },
            properties: { category: r.category, severity: r.severity },
          })),
        },
      },
      results,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}
