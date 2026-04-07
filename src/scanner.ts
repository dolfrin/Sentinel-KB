import * as fs from "fs";
import * as path from "path";
import { Rule, Severity, allRules } from "./rules.js";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: string;
  message: string;
  file: string;
  line: number;
  snippet: string;
}

export interface AuditReport {
  timestamp: string;
  projectPath: string;
  totalFiles: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  categories: Record<string, number>;
}

/** Recursively collect files matching glob-like patterns */
function collectFiles(dir: string, patterns: string[]): string[] {
  const results: string[] = [];
  const seen = new Set<string>();

  function matchesPattern(filePath: string, pattern: string): boolean {
    const fileName = path.basename(filePath);
    // Simple glob: **/*.ext or **/Name*.ext
    if (pattern.startsWith("**/")) {
      const rest = pattern.slice(3);
      if (rest.includes("*")) {
        const regex = new RegExp("^" + rest.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
        return regex.test(fileName);
      }
      return fileName === rest || filePath.endsWith(rest);
    }
    return fileName === pattern;
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
        if (
          ["node_modules", ".git", "build", "target", ".gradle", ".idea", ".cxx", "dist"].includes(
            entry.name
          )
        ) {
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
      for (const bp of rule.badPatterns) {
        for (let i = 0; i < lines.length; i++) {
          // Check individual lines
          if (bp.pattern.test(lines[i])) {
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
          }
        }

        // Also check multi-line patterns (across whole file)
        const source = bp.pattern.source;
        if (source.includes("[\\s\\S]") || source.includes("[\\S\\s]")) {
          // Multi-line pattern — run against chunks of content
          const chunkSize = 2000;
          for (let offset = 0; offset < content.length; offset += chunkSize - 500) {
            const chunk = content.substring(offset, offset + chunkSize);
            if (bp.pattern.test(chunk)) {
              // Find approximate line number
              const beforeChunk = content.substring(0, offset);
              const approxLine = beforeChunk.split("\n").length;
              // Avoid duplicate findings
              const isDuplicate = findings.some(
                (f) => f.ruleId === rule.id && f.file === relPath && Math.abs(f.line - approxLine) < 10
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
export function audit(projectDir: string, options?: { categories?: string[]; severity?: Severity[] }): AuditReport {
  const rules = allRules.filter((r) => {
    if (options?.categories && !options.categories.includes(r.category)) return false;
    if (options?.severity && !options.severity.includes(r.severity)) return false;
    return true;
  });

  // Collect all unique file patterns
  const allPatterns = [...new Set(rules.flatMap((r) => r.filePatterns))];
  const files = collectFiles(projectDir, allPatterns);

  const allFindings: Finding[] = [];

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    // Find applicable rules for this file
    const applicableRules = rules.filter((r) =>
      r.filePatterns.some((p) => {
        const fileName = path.basename(file);
        if (p.startsWith("**/")) {
          const rest = p.slice(3);
          if (rest.includes("*")) {
            const regex = new RegExp("^" + rest.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$");
            return regex.test(fileName);
          }
          return fileName === rest || file.endsWith(rest);
        }
        return fileName === p;
      })
    );

    if (applicableRules.length > 0) {
      const findings = scanFile(file, content, applicableRules, projectDir);
      allFindings.push(...findings);
    }
  }

  // Check required patterns (absence-based findings)
  for (const rule of rules) {
    if (rule.requiredPatterns) {
      for (const rp of rule.requiredPatterns) {
        const patternFiles = collectFiles(projectDir, [rp.filePattern]);
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
          const ruleFiles = collectFiles(projectDir, rule.filePatterns);
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

  // Sort by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Build summary
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categories: Record<string, number> = {};
  for (const f of allFindings) {
    summary[f.severity]++;
    categories[f.category] = (categories[f.category] || 0) + 1;
  }

  return {
    timestamp: new Date().toISOString(),
    projectPath: projectDir,
    totalFiles: files.length,
    findings: allFindings,
    summary,
    categories,
  };
}

/** Format report as human-readable text */
export function formatReport(report: AuditReport): string {
  const lines: string[] = [];

  lines.push("═══════════════════════════════════════════════════════");
  lines.push("  MESSENGER SECURITY AUDIT REPORT");
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
        lines.push("");
      }
    }
  }

  lines.push("═══════════════════════════════════════════════════════");
  return lines.join("\n");
}
