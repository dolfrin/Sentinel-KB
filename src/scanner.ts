import * as fs from "fs";
import * as path from "path";
import picomatch from "picomatch";
import { Rule, Severity, allRules } from "./rules.js";
import { triageFindings, TriageDecision } from "./triage.js";
import { runSemgrep, isSemgrepAvailable, SemgrepOptions } from "./semgrep.js";

/** Numeric severity ranking — lower value = more severe */
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Expand severity thresholds into the full set of severities at or above each
 * threshold.  Each entry is treated as a minimum — all severities at that level
 * or higher are included.  Multiple entries use the loosest (most inclusive).
 *
 * Examples:
 *   ["high"]           → {critical, high}
 *   ["medium"]         → {critical, high, medium}
 *   ["critical"]       → {critical}
 *   ["critical","low"] → {critical, high, medium, low}
 */
function expandSeverityThresholds(thresholds: Severity[]): Set<Severity> {
  const maxRank = Math.max(...thresholds.map((s) => SEVERITY_RANK[s]));
  return new Set(ALL_SEVERITIES.filter((s) => SEVERITY_RANK[s] <= maxRank));
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: string;
  message: string;
  file: string;
  line: number;
  snippet: string;
  totalOccurrences?: number;       // total times this rule fired across project
  additionalLocations?: string[];  // file:line for locations beyond the shown MAX_PER_RULE
}

/** A single location where a rule matched */
export interface Occurrence {
  file: string;
  line: number;
  snippet: string;
  message: string;  // The specific bad-pattern message for this occurrence
}

/** Aggregated view: one Issue per rule that fired, with all its occurrences */
export interface Issue {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: string;
  message: string;
  occurrences: Occurrence[];          // ALL locations where this rule fired
  displayedOccurrences: Occurrence[]; // First MAX_PER_RULE (for display)
  totalOccurrences: number;           // occurrences.length (convenience)
}

export interface AuditReport {
  timestamp: string;
  projectPath: string;
  totalFiles: number;
  findings: Finding[];                 // Flattened view (first MAX_PER_RULE per rule) — backward compat
  issues?: Issue[];                    // Aggregated view: one entry per rule (new)
  summary: Record<Severity, number>;   // Counts deduped findings (backward compat)
  categories: Record<string, number>;  // Counts deduped findings (backward compat)
  totalIssues?: number;                // Number of distinct issues (rules that fired)
  triage?: {                           // Phase-1 triage results (FP filtering, severity adjustments)
    droppedCount: number;
    downgradedCount: number;
    decisions: TriageDecision[];
  };
}

// Directories that are ALWAYS skipped — build artifacts, dependencies, VCS
const coreSkipDirs = new Set([
  // Build & dependency dirs
  "node_modules", ".git", "build", "target", ".gradle", ".idea", ".cxx", "dist", "out",
  // Third-party / vendor / generated / submodules
  "vendor", "third_party", "thirdparty", "third-party", "external", "generated", "proto",
  "submodules", "Submodules",
]);

// Directories skipped by default but overridable via includeAllDirs
const defaultSkipDirs = new Set([
  // Test directories
  "__tests__", "test", "tests", "Tests", "androidTest", "benchmarkShared", "testFixtures",
  "androidBenchmark", "androidInstrumentedTest", "commonTest", "jvmTest",
  // Demo / sample / e2e
  "demo", "sample", "samples", "example", "examples", "fixtures", "e2e", "cypress", "playwright",
  // Assets (bundled JS like ace.min.js)
  "assets",
  // Documentation source
  "docs_src", "docs",
  // Ruby/RSpec test dirs
  "spec",
  // Development environment / tooling
  "devenv", "testdata", "testing", "test-plugins",
]);

/** Recursively collect files matching glob-like patterns */
function collectFiles(dir: string, patterns: string[], includeAllDirs?: boolean): string[] {
  const results: string[] = [];
  const seen = new Set<string>();

  function matchesPattern(filePath: string, pattern: string): boolean {
    return picomatch(pattern)(filePath);
  }

  function walk(currentDir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      // Skip common non-source directories
      if (entry.isDirectory()) {
        if (coreSkipDirs.has(entry.name)
          || (!includeAllDirs && defaultSkipDirs.has(entry.name))
          || entry.name.startsWith("e2e-")
          || entry.name.startsWith("__")) {
          continue;
        }
        walk(fullPath);
      } else if (entry.isFile()) {
        const relPath = path.relative(dir, fullPath);
        if (!seen.has(relPath)) {
          for (const pattern of patterns) {
            if (matchesPattern(relPath, pattern)) {
              seen.add(relPath);
              results.push(fullPath);
              break;
            }
          }
        }
      }
    }
  }

  walk(dir);
  return results;
}

/** Scan a single file against a set of rules */
export function scanFile(filePath: string, content: string, rules: Rule[], projectDir: string): Finding[] {
  const findings: Finding[] = [];
  const relPath = path.relative(projectDir, filePath);
  const lines = content.split("\n");

  for (const rule of rules) {
    // Check bad patterns
    if (rule.badPatterns) {
      let ruleFindingsCount = 0;
      const maxFindingsPerRule = 5; // Cap findings per rule per file to avoid noise

      for (const bp of rule.badPatterns) {
        if (ruleFindingsCount >= maxFindingsPerRule) break;

        for (let i = 0; i < lines.length; i++) {
          if (ruleFindingsCount >= maxFindingsPerRule) break;
          // Check individual lines (skip lines with suppression annotations)
          if (bp.pattern.test(lines[i]) && !/(?:#nosec|nolint|NOSONAR|NOLINT|nosec|@suppress)/.test(lines[i])) {
            findings.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              category: rule.category,
              message: bp.message,
              file: relPath,
              line: i + 1,
              snippet: lines[i].trim().substring(0, 120),
            });
            ruleFindingsCount++;
          }
        }

        // Also check multi-line patterns (across whole file)
        // Only if the pattern actually uses cross-line matching AND we haven't already found
        // this rule+pattern on single-line scan (to avoid duplicates)
        const source = bp.pattern.source;
        if (source.includes("[\\s\\S]") || source.includes("[\\S\\s]")) {
          const alreadyFoundForThisPattern = findings.some(
            (f) => f.ruleId === rule.id && f.file === relPath && f.message === bp.message
          );
          if (!alreadyFoundForThisPattern) {
            // Multi-line pattern — run against chunks of content
            const chunkSize = 2000;
            let multiLineFindings = 0;
            const maxMultiLinePerPattern = 3; // Cap to avoid flood from repetitive code
            for (let offset = 0; offset < content.length && multiLineFindings < maxMultiLinePerPattern; offset += chunkSize - 500) {
              const chunk = content.substring(offset, offset + chunkSize);
              if (bp.pattern.test(chunk)) {
                const beforeChunk = content.substring(0, offset);
                const approxLine = beforeChunk.split("\n").length;
                // Wider dedup window (50 lines) to avoid repeated findings in similar code
                const isDuplicate = findings.some(
                  (f) => f.ruleId === rule.id && f.file === relPath && Math.abs(f.line - approxLine) < 50
                );
                if (!isDuplicate) {
                  findings.push({
                    ruleId: rule.id,
                    ruleName: rule.name,
                    severity: rule.severity,
                    category: rule.category,
                    message: bp.message,
                    file: relPath,
                    line: approxLine,
                    snippet: chunk.substring(0, 120).replace(/\n/g, " ").trim(),
                  });
                  multiLineFindings++;
                }
              }
            }
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Scan a single file for security vulnerabilities.
 * Fast path: reads one file, matches applicable rules by file pattern, runs scanFile().
 * Skips absence-based (requiredPatterns) checks since those are project-wide.
 * No project-wide dedup — returns all findings for this file.
 */
export function auditFile(filePath: string, options?: { categories?: string[]; severity?: Severity[] }): Finding[] {
  const expandedSeverities = options?.severity ? expandSeverityThresholds(options.severity) : null;

  const rules = allRules.filter((r) => {
    if (options?.categories && !options.categories.includes(r.category)) return false;
    if (expandedSeverities && !expandedSeverities.has(r.severity)) return false;
    return true;
  });

  const fileName = path.basename(filePath);

  // Skip minified files
  if (fileName.includes(".min.") || fileName.endsWith("-min.js") || fileName.endsWith("-min.css")) {
    return [];
  }

  // Skip preview/mock/fake/test data files
  if (/(?:Preview|Mock|Fake|Dummy|Stub|Fixture|__preview__|__mock__)/.test(fileName)) {
    return [];
  }

  // Skip test files
  if (/_test\.go$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|\.e2e-spec\.[jt]sx?$|\.e2e\.[jt]sx?$|_test\.py$|_test\.rs$|Test\.java$|Test\.kt$/.test(fileName)) {
    return [];
  }

  let content: string;
  try {
    content = fs.readFileSync(filePath, "utf-8");
  } catch (err: any) {
    throw new Error(`Cannot read file: ${err.message}`);
  }

  // Skip files that are too large (likely generated/bundled) — over 500KB
  if (content.length > 500_000) {
    return [];
  }

  // Skip files with very long lines (minified/generated code)
  const firstFewLines = content.slice(0, 10_000).split("\n");
  if (firstFewLines.some((line) => line.length > 1000)) {
    return [];
  }

  // Skip auto-generated files
  const header = content.slice(0, 500).toLowerCase();
  if (
    header.includes("auto-generated") ||
    header.includes("autogenerated") ||
    header.includes("do not edit") ||
    header.includes("generated by") ||
    header.includes("this file is generated")
  ) {
    return [];
  }

  // Allow files to opt out of scanning with a sentinel comment
  if (content.startsWith("// sentinel-kb-ignore-file") || content.includes("\n// sentinel-kb-ignore-file")) {
    return [];
  }

  // For single-file scan, use the absolute path for rule matching so that
  // directory-based patterns like "**/handlers/*.rs" work correctly.
  // scanFile() computes finding paths relative to projectDir.
  const projectDir = path.dirname(filePath);

  // Match rules using both the basename and the full path — a pattern like "*.ts"
  // matches the basename, while "**/handlers/*.rs" matches the full path.
  const applicableRules = rules.filter((r) =>
    r.filePatterns.some((p) => picomatch(p)(filePath) || picomatch(p)(path.basename(filePath)))
  );

  if (applicableRules.length === 0) {
    return [];
  }

  const findings = scanFile(filePath, content, applicableRules, projectDir);

  // Sort by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return findings;
}

/** Run full audit on a project directory */
export function audit(
  projectDir: string,
  options?: {
    categories?: string[];
    severity?: Severity[];
    includeAllDirs?: boolean;
    triage?: boolean;
    semgrep?: boolean | SemgrepOptions;
  }
): AuditReport {
  // Expand severity filter: each provided level acts as a minimum threshold,
  // so ["high"] includes critical + high, ["medium"] includes critical + high + medium, etc.
  const expandedSeverities = options?.severity ? expandSeverityThresholds(options.severity) : null;

  const rules = allRules.filter((r) => {
    if (options?.categories && !options.categories.includes(r.category)) return false;
    if (expandedSeverities && !expandedSeverities.has(r.severity)) return false;
    return true;
  });

  // Collect all unique file patterns
  const allPatterns = [...new Set(rules.flatMap((r) => r.filePatterns))];
  const files = collectFiles(projectDir, allPatterns, options?.includeAllDirs);

  const allFindings: Finding[] = [];

  for (const file of files) {
    const fileName = path.basename(file);

    // Skip minified files — they are third-party code, not user source
    if (fileName.includes(".min.") || fileName.endsWith("-min.js") || fileName.endsWith("-min.css")) {
      continue;
    }

    // Skip preview/mock/fake/test data files — they contain intentional dummy data
    if (/(?:Preview|Mock|Fake|Dummy|Stub|Fixture|__preview__|__mock__)/.test(fileName)) {
      continue;
    }

    // Skip test files — they contain intentional test data, fake credentials, etc.
    if (/_test\.go$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|\.e2e-spec\.[jt]sx?$|\.e2e\.[jt]sx?$|_test\.py$|_test\.rs$|Test\.java$|Test\.kt$/.test(fileName)) {
      continue;
    }

    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    // Skip files that are too large (likely generated/bundled) — over 500KB
    if (content.length > 500_000) {
      continue;
    }

    // Skip files with very long lines (minified/generated code)
    const firstFewLines = content.slice(0, 10_000).split("\n");
    if (firstFewLines.some((line) => line.length > 1000)) {
      continue;
    }

    // Skip auto-generated files
    const header = content.slice(0, 500).toLowerCase();
    if (
      header.includes("auto-generated") ||
      header.includes("autogenerated") ||
      header.includes("do not edit") ||
      header.includes("generated by") ||
      header.includes("this file is generated")
    ) {
      continue;
    }

    // Allow files to opt out of scanning with a sentinel comment
    if (content.startsWith("// sentinel-kb-ignore-file") || content.includes("\n// sentinel-kb-ignore-file")) {
      continue;
    }

    // Find applicable rules for this file
    const relFile = path.relative(projectDir, file);
    const applicableRules = rules.filter((r) =>
      r.filePatterns.some((p) => picomatch(p)(relFile))
    );

    if (applicableRules.length > 0) {
      const findings = scanFile(file, content, applicableRules, projectDir);
      allFindings.push(...findings);
    }
  }

  // Check required patterns (absence-based findings)
  // Only report absence if the project actually contains files matching the rule's domain
  for (const rule of rules) {
    if (rule.requiredPatterns) {
      // Check if the project has any files that match the rule's filePatterns
      // If no domain files exist, the rule is irrelevant to this project
      const domainFiles = collectFiles(projectDir, rule.filePatterns, options?.includeAllDirs);
      if (domainFiles.length === 0) {
        // No domain-relevant files — skip absence checks for this rule entirely
        continue;
      }

      for (const rp of rule.requiredPatterns) {
        const patternFiles = collectFiles(projectDir, [rp.filePattern], options?.includeAllDirs);
        let found = false;
        for (const file of patternFiles) {
          try {
            const content = fs.readFileSync(file, "utf-8");
            if (rp.pattern.test(content)) {
              found = true;
              break;
            }
          } catch {
            continue;
          }
        }
        // Also search all files matching rule.filePatterns
        if (!found) {
          const ruleFiles = domainFiles;
          for (const file of ruleFiles) {
            try {
              const content = fs.readFileSync(file, "utf-8");
              if (rp.pattern.test(content)) {
                found = true;
                break;
              }
            } catch {
              continue;
            }
          }
        }
        if (!found) {
          allFindings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            message: rp.message,
            file: "(project-wide)",
            line: 0,
            snippet: "",
          });
        }
      }
    }
  }

  // ── Optional Semgrep pass: AST-based analysis ─────────────────
  // Off by default — enable with options.semgrep = true (or pass config object).
  // Returns no findings if semgrep CLI is not installed.
  if (options?.semgrep) {
    const semgrepOptions = typeof options.semgrep === "object" ? options.semgrep : undefined;
    const semgrepFindings = runSemgrep(projectDir, semgrepOptions);
    allFindings.push(...semgrepFindings);
  }

  // ── Triage: filter false positives and downgrade severity by context ──
  // Default: enabled. Set options.triage = false to skip (debugging / raw output).
  const triageEnabled = options?.triage !== false;
  let triagedFindings: Finding[] = allFindings;
  let triageDecisions: TriageDecision[] = [];
  let triageDropped = 0;
  let triageDowngraded = 0;
  if (triageEnabled) {
    const result = triageFindings(allFindings, projectDir);
    triagedFindings = result.kept;
    triageDecisions = [...result.dropped, ...result.downgraded];
    triageDropped = result.dropped.length;
    triageDowngraded = result.downgraded.length;
  }

  // ── Build Issue[] (aggregated view: one Issue per ruleId) ──
  // Group all raw findings by ruleId, preserving insertion order.
  const MAX_PER_RULE = 3;
  const issueMap = new Map<string, { meta: Finding; occurrences: Occurrence[] }>();

  for (const f of triagedFindings) {
    let entry = issueMap.get(f.ruleId);
    if (!entry) {
      entry = { meta: f, occurrences: [] };
      issueMap.set(f.ruleId, entry);
    }
    entry.occurrences.push({ file: f.file, line: f.line, snippet: f.snippet, message: f.message });
  }

  const issues: Issue[] = [];
  for (const [, { meta, occurrences }] of issueMap) {
    issues.push({
      ruleId: meta.ruleId,
      ruleName: meta.ruleName,
      severity: meta.severity,
      category: meta.category,
      message: meta.message,
      occurrences,
      displayedOccurrences: occurrences.slice(0, MAX_PER_RULE),
      totalOccurrences: occurrences.length,
    });
  }

  // Sort issues by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  issues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // ── Derive findings[] from issues (backward-compatible flattened view) ──
  // First MAX_PER_RULE occurrences per issue, annotated with totalOccurrences/additionalLocations.
  const dedupedFindings: Finding[] = [];
  for (const issue of issues) {
    const extras = issue.occurrences.slice(MAX_PER_RULE).map((o) => `${o.file}:${o.line}`);

    for (const occ of issue.displayedOccurrences) {
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
      if (issue.totalOccurrences > 1) {
        finding.totalOccurrences = issue.totalOccurrences;
      }
      if (extras.length > 0) {
        finding.additionalLocations = extras;
      }
      dedupedFindings.push(finding);
    }
  }

  // Build summary — count distinct issues (not flattened findings) so summary.critical + summary.high + ...
  // equals totalIssues, giving consumers a consistent picture.
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categories: Record<string, number> = {};
  for (const issue of issues) {
    summary[issue.severity]++;
    categories[issue.category] = (categories[issue.category] || 0) + 1;
  }

  return {
    timestamp: new Date().toISOString(),
    projectPath: projectDir,
    totalFiles: files.length,
    findings: dedupedFindings,
    issues,
    summary,
    categories,
    totalIssues: issues.length,
    triage: triageEnabled ? {
      droppedCount: triageDropped,
      downgradedCount: triageDowngraded,
      decisions: triageDecisions,
    } : undefined,
  };
}

/** Format report as human-readable text */
export function formatReport(report: AuditReport): string {
  const lines: string[] = [];

  // Use issues[] when available (new model), fall back to findings[] (backward compat)
  const issues = report.issues;
  const totalIssues = report.totalIssues ?? issues?.length ?? 0;

  lines.push("═══════════════════════════════════════════════════════");
  lines.push("  Sentinel-KB Security Audit Report");
  lines.push("═══════════════════════════════════════════════════════");
  lines.push(`  Project: ${report.projectPath}`);
  lines.push(`  Date:    ${report.timestamp}`);
  lines.push(`  Files:   ${report.totalFiles} scanned`);
  lines.push(`  Issues:  ${totalIssues} distinct`);
  lines.push("───────────────────────────────────────────────────────");
  // summary now counts distinct issues (not flattened findings)
  lines.push(
    `  🔴 CRITICAL: ${report.summary.critical}  🟠 HIGH: ${report.summary.high}  🟡 MEDIUM: ${report.summary.medium}  🔵 LOW: ${report.summary.low}`
  );

  if (report.triage) {
    lines.push(
      `  Triage: ${report.triage.droppedCount} false positives dropped, ${report.triage.downgradedCount} downgraded by context`
    );
  }

  lines.push("───────────────────────────────────────────────────────");

  if (report.findings.length === 0) {
    lines.push("\n  ✅ No findings — all checks passed!\n");
  } else if (issues && issues.length > 0) {
    // New model: render from issues[] (aggregated view)
    const byCategory: Record<string, Issue[]> = {};
    for (const issue of issues) {
      if (!byCategory[issue.category]) byCategory[issue.category] = [];
      byCategory[issue.category].push(issue);
    }

    for (const [category, catIssues] of Object.entries(byCategory)) {
      lines.push(`\n  ── ${category} (${catIssues.length} issues) ──\n`);
      for (const issue of catIssues) {
        const icon =
          issue.severity === "critical" ? "🔴" : issue.severity === "high" ? "🟠" : issue.severity === "medium" ? "🟡" : "🔵";
        lines.push(`  ${icon} [${issue.ruleId}] ${issue.ruleName}`);
        lines.push(`     ${issue.message}`);

        // Show displayed occurrences
        for (const occ of issue.displayedOccurrences) {
          if (occ.file !== "(project-wide)") {
            lines.push(`     ${occ.file}:${occ.line}`);
          }
          if (occ.snippet) {
            lines.push(`     > ${occ.snippet}`);
          }
        }

        if (issue.totalOccurrences > issue.displayedOccurrences.length) {
          const moreCount = issue.totalOccurrences - issue.displayedOccurrences.length;
          lines.push(`     ... and ${moreCount} more (${issue.totalOccurrences} total)`);
        }
        lines.push("");
      }
    }
  } else {
    // Legacy fallback: render from findings[] when issues[] is not present
    const byCategory: Record<string, Finding[]> = {};
    for (const f of report.findings) {
      if (!byCategory[f.category]) byCategory[f.category] = [];
      byCategory[f.category].push(f);
    }

    for (const [category, findings] of Object.entries(byCategory)) {
      lines.push(`\n  ── ${category} (${findings.length}) ──\n`);
      for (const f of findings) {
        const icon =
          f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : f.severity === "medium" ? "🟡" : "🔵";
        lines.push(`  ${icon} [${f.ruleId}] ${f.ruleName}`);
        if (f.file !== "(project-wide)") {
          lines.push(`     ${f.file}:${f.line}`);
        }
        lines.push(`     ${f.message}`);
        if (f.snippet) {
          lines.push(`     > ${f.snippet}`);
        }
        if (f.totalOccurrences && f.totalOccurrences > 1 && f.additionalLocations && f.additionalLocations.length > 0) {
          const extraList = f.additionalLocations.join(", ");
          lines.push(`     Found in ${f.totalOccurrences} locations (${f.additionalLocations.length} more: ${extraList})`);
        }
        lines.push("");
      }
    }
  }

  lines.push("═══════════════════════════════════════════════════════");
  return lines.join("\n");
}
