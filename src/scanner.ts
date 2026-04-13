import * as fs from "fs";
import * as path from "path";
import picomatch from "picomatch";
import { Rule, Severity, allRules } from "./rules.js";

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

export interface AuditReport {
  timestamp: string;
  projectPath: string;
  totalFiles: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  categories: Record<string, number>;
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
function scanFile(filePath: string, content: string, rules: Rule[], projectDir: string): Finding[] {
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

/** Run full audit on a project directory */
export function audit(projectDir: string, options?: { categories?: string[]; severity?: Severity[]; includeAllDirs?: boolean }): AuditReport {
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

  // Deduplicate: cap at 3 findings per rule across the entire project.
  // An audit reports distinct issues, not every occurrence of the same pattern.
  // If a rule fires 89 times, that's ONE issue with note "found in N locations".
  const MAX_PER_RULE = 3;
  const ruleHitCounts: Record<string, number> = {};
  const ruleTotalCounts: Record<string, number> = {};
  const ruleExtraLocations: Record<string, string[]> = {};

  // First pass: count totals per rule and collect all locations beyond MAX_PER_RULE
  for (const f of allFindings) {
    ruleTotalCounts[f.ruleId] = (ruleTotalCounts[f.ruleId] || 0) + 1;
  }

  // Second pass: keep only first MAX_PER_RULE per rule, collect overflow locations
  const dedupedFindings: Finding[] = [];
  for (const f of allFindings) {
    ruleHitCounts[f.ruleId] = (ruleHitCounts[f.ruleId] || 0) + 1;
    if (ruleHitCounts[f.ruleId] <= MAX_PER_RULE) {
      dedupedFindings.push(f);
    } else {
      // Track overflow locations as structured metadata
      if (!ruleExtraLocations[f.ruleId]) ruleExtraLocations[f.ruleId] = [];
      ruleExtraLocations[f.ruleId].push(`${f.file}:${f.line}`);
    }
  }

  // Third pass: annotate kept findings with totalOccurrences and additionalLocations
  for (const f of dedupedFindings) {
    const total = ruleTotalCounts[f.ruleId]!;
    if (total > 1) {
      f.totalOccurrences = total;
    }
    const extras = ruleExtraLocations[f.ruleId];
    if (extras && extras.length > 0) {
      f.additionalLocations = extras;
    }
  }

  // Sort by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  dedupedFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Build summary
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categories: Record<string, number> = {};
  for (const f of dedupedFindings) {
    summary[f.severity]++;
    categories[f.category] = (categories[f.category] || 0) + 1;
  }

  return {
    timestamp: new Date().toISOString(),
    projectPath: projectDir,
    totalFiles: files.length,
    findings: dedupedFindings,
    summary,
    categories,
  };
}

/** Format report as human-readable text */
export function formatReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push("═══════════════════════════════════════════════════════");
  lines.push("  Sentinel-KB Security Audit Report");
  lines.push("═══════════════════════════════════════════════════════");
  lines.push(`  Project: ${report.projectPath}`);
  lines.push(`  Date:    ${report.timestamp}`);
  lines.push(`  Files:   ${report.totalFiles} scanned`);
  lines.push("───────────────────────────────────────────────────────");
  lines.push(
    `  🔴 CRITICAL: ${report.summary.critical}  🟠 HIGH: ${report.summary.high}  🟡 MEDIUM: ${report.summary.medium}  🔵 LOW: ${report.summary.low}`
  );
  lines.push("───────────────────────────────────────────────────────");

  if (report.findings.length === 0) {
    lines.push("\n  ✅ No findings — all checks passed!\n");
  } else {
    const byCategory: Record<string, typeof report.findings> = {};
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
