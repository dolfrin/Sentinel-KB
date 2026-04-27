// sentinel-kb-ignore-file
// Optional Semgrep integration — adds AST-based static analysis on top of regex rules.
// If semgrep CLI is not installed, this module returns no findings and logs a notice.
//
// Install: pip install semgrep  (or `brew install semgrep` on mac)
// Docs:    https://semgrep.dev

import { execFileSync } from "child_process";
import * as path from "path";
import type { Finding } from "./scanner.js";
import type { Severity } from "./rules.js";

let _semgrepAvailable: boolean | null = null;

/** Cached availability check. Returns true if `semgrep` CLI is installed and runnable. */
export function isSemgrepAvailable(): boolean {
  if (_semgrepAvailable !== null) return _semgrepAvailable;
  try {
    execFileSync("semgrep", ["--version"], { stdio: "ignore", timeout: 5000 });
    _semgrepAvailable = true;
  } catch {
    _semgrepAvailable = false;
  }
  return _semgrepAvailable;
}

// ─── Severity mapping ──────────────────────────────────────────

/**
 * Semgrep severity levels:
 *   ERROR    → high
 *   WARNING  → medium
 *   INFO     → low
 *
 * Semgrep also exposes optional metadata.severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
 * which we prefer when present.
 */
function mapSemgrepSeverity(sev: string, metaSev?: string): Severity {
  if (metaSev) {
    const m = metaSev.toLowerCase();
    if (m === "critical") return "critical";
    if (m === "high" || m === "error") return "high";
    if (m === "medium" || m === "warning") return "medium";
    if (m === "low") return "low";
    if (m === "info") return "info";
  }
  const s = sev.toUpperCase();
  if (s === "ERROR") return "high";
  if (s === "WARNING") return "medium";
  if (s === "INFO") return "low";
  return "medium";
}

// ─── Category mapping ──────────────────────────────────────────

/**
 * Map a Semgrep rule_id (e.g. "javascript.lang.security.audit.xss")
 * to one of our existing category names. Falls back to "Static Analysis"
 * when no specific mapping fits.
 */
function mapSemgrepCategory(ruleId: string, metaCategory?: string, metaCwe?: string[]): string {
  const id = ruleId.toLowerCase();
  if (metaCategory) {
    const c = metaCategory.toLowerCase();
    if (c.includes("crypto")) return "Cryptography";
    if (c.includes("auth")) return "Authentication";
    if (c.includes("injection")) return "Input Validation";
  }
  if (metaCwe && metaCwe.length > 0) {
    const cwe = metaCwe[0].toUpperCase();
    if (cwe.includes("CWE-79") || cwe.includes("CWE-80")) return "Cross-Site Scripting";
    if (cwe.includes("CWE-89")) return "Input Validation";
    if (cwe.includes("CWE-22")) return "Path Traversal";
    if (cwe.includes("CWE-78") || cwe.includes("CWE-94")) return "Code Injection";
    if (cwe.includes("CWE-327") || cwe.includes("CWE-326") || cwe.includes("CWE-330")) return "Cryptography";
    if (cwe.includes("CWE-287") || cwe.includes("CWE-306")) return "Authentication";
    if (cwe.includes("CWE-798") || cwe.includes("CWE-259")) return "Secrets";
    if (cwe.includes("CWE-352")) return "CSRF";
    if (cwe.includes("CWE-918")) return "SSRF";
    if (cwe.includes("CWE-611")) return "XML External Entity";
  }
  if (id.includes("xss")) return "Cross-Site Scripting";
  if (id.includes("sql") || id.includes("injection")) return "Input Validation";
  if (id.includes("crypto") || id.includes("hash") || id.includes("cipher")) return "Cryptography";
  if (id.includes("auth") || id.includes("jwt") || id.includes("session")) return "Authentication";
  if (id.includes("secret") || id.includes("hardcoded")) return "Secrets";
  if (id.includes("path") || id.includes("traversal")) return "Path Traversal";
  if (id.includes("redos") || id.includes("regex")) return "ReDoS";
  if (id.includes("csrf")) return "CSRF";
  if (id.includes("ssrf")) return "SSRF";
  if (id.includes("deserial")) return "Deserialization";
  return "Static Analysis";
}

// ─── Output parsing ────────────────────────────────────────────

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    lines?: string;
    metadata?: {
      category?: string;
      cwe?: string[];
      severity?: string;
      confidence?: string;
    };
  };
}

interface SemgrepOutput {
  results: SemgrepResult[];
  errors: unknown[];
  paths?: { scanned: string[] };
}

function semgrepResultToFinding(r: SemgrepResult, projectDir: string): Finding {
  const meta = r.extra.metadata || {};
  const severity = mapSemgrepSeverity(r.extra.severity, meta.severity);
  const category = mapSemgrepCategory(r.check_id, meta.category, meta.cwe);
  const relPath = path.relative(projectDir, r.path) || r.path;
  const snippet = (r.extra.lines || "").trim().substring(0, 200);
  return {
    ruleId: `SEMGREP/${r.check_id}`,
    ruleName: r.check_id.split(".").slice(-1)[0] || r.check_id,
    severity,
    category,
    message: r.extra.message,
    file: relPath,
    line: r.start.line,
    snippet,
  };
}

// ─── Main runner ───────────────────────────────────────────────

export interface SemgrepOptions {
  /** Semgrep config to use (default: "auto") — try "p/security-audit", "p/owasp-top-ten", or path to custom rules */
  config?: string;
  /** Per-run timeout in seconds (default: 300) */
  timeoutSeconds?: number;
  /** Max bytes of output to accept (default: 50MB) */
  maxBuffer?: number;
}

/**
 * Run semgrep against a project and return findings normalized into our Finding shape.
 * Returns [] if semgrep is unavailable or fails — never throws.
 */
export function runSemgrep(projectDir: string, options?: SemgrepOptions): Finding[] {
  if (!isSemgrepAvailable()) return [];

  const config = options?.config ?? "auto";
  const timeout = (options?.timeoutSeconds ?? 300) * 1000;
  const maxBuffer = options?.maxBuffer ?? 50 * 1024 * 1024;

  let raw: string;
  try {
    raw = execFileSync(
      "semgrep",
      [
        "--config", config,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout", "30",
        "--metrics", "off",
        projectDir,
      ],
      { encoding: "utf-8", timeout, maxBuffer, stdio: ["ignore", "pipe", "pipe"] }
    );
  } catch (err: any) {
    // semgrep returns non-zero when findings exist OR on errors — try to parse anyway
    raw = (err.stdout || "").toString();
    if (!raw) return [];
  }

  let parsed: SemgrepOutput;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }

  if (!parsed.results || !Array.isArray(parsed.results)) return [];

  return parsed.results.map((r) => semgrepResultToFinding(r, projectDir));
}
