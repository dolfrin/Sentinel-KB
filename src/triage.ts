// sentinel-kb-ignore-file
// Triage layer — filters false positives and downgrades severity by context.
// Runs after the static scanner, before findings are reported.

import * as fs from "fs";
import * as path from "path";
import type { Finding } from "./scanner.js";
import type { Severity } from "./rules.js";

// ─── Config files: never report findings on these ──────────────

const CONFIG_FILE_BLOCKLIST = new Set([
  // Mobile platform configs (committed by convention, restricted by SHA + bundle id)
  "google-services.json",
  "GoogleService-Info.plist",
  "firebase.json",
  ".firebaserc",
  "apple-app-site-association",
  // Lockfiles / generated metadata
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.lock",
  "poetry.lock",
  "Pipfile.lock",
  "go.sum",
  "composer.lock",
  // Templates and examples
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.local.example",
]);

const CONFIG_FILE_SUFFIX_PATTERNS: RegExp[] = [
  /\.example$/i,
  /\.sample$/i,
  /\.template$/i,
  /\.dist$/i,
];

function isConfigFile(filePath: string): boolean {
  const base = path.basename(filePath);
  if (CONFIG_FILE_BLOCKLIST.has(base)) return true;
  return CONFIG_FILE_SUFFIX_PATTERNS.some((p) => p.test(base));
}

// ─── Test paths: severity downgrade ────────────────────────────

const TEST_PATH_SEGMENTS = new Set([
  "test", "tests", "__tests__", "__test__", "spec", "specs",
  "test_helpers", "testHelpers", "testFixtures", "fixtures",
  "mocks", "__mocks__", "stubs",
  "androidTest", "androidInstrumentedTest", "commonTest", "jvmTest",
  "androidBenchmark", "benchmarkShared",
  "e2e", "playwright", "cypress", "integration-tests",
]);

function isTestPath(filePath: string): boolean {
  const segments = filePath.split(/[/\\]/);
  return segments.some((s) => TEST_PATH_SEGMENTS.has(s));
}

// ─── Inline test block detection (Rust, Java, etc.) ────────────

const TEST_BLOCK_OPENERS: RegExp[] = [
  /#\[cfg\(test\)\]/,                              // Rust
  /#\[cfg\(any\(test\b/,                           // Rust multi-cfg
  /^\s*pub\s+mod\s+(test_helpers|tests|test)\b/m,  // Rust test module
  /^\s*mod\s+(test_helpers|tests|test)\s*\{/m,     // Rust private test mod
  /@TestOnly\b|@VisibleForTesting\b/,              // Java/Kotlin annotation
];

interface BlockRange { start: number; end: number; }

/** Find line ranges that are inside test-only blocks (cfg(test), mod tests, etc.) */
function findTestBlocks(content: string): BlockRange[] {
  const lines = content.split("\n");
  const blocks: BlockRange[] = [];

  for (let i = 0; i < lines.length; i++) {
    if (!TEST_BLOCK_OPENERS.some((p) => p.test(lines[i]))) continue;

    // Find first opening brace from this line forward
    let openLine = -1;
    for (let j = i; j < Math.min(lines.length, i + 5); j++) {
      if (lines[j].includes("{")) { openLine = j; break; }
    }
    if (openLine === -1) continue;

    // Walk forward, tracking brace depth, until depth returns to 0
    let depth = 0;
    let endLine = -1;
    for (let j = openLine; j < lines.length; j++) {
      for (const c of lines[j]) {
        if (c === "{") depth++;
        else if (c === "}") {
          depth--;
          if (depth === 0) { endLine = j; break; }
        }
      }
      if (endLine !== -1) break;
    }
    if (endLine !== -1) {
      blocks.push({ start: i + 1, end: endLine + 1 }); // 1-indexed line numbers
    }
  }

  return blocks;
}

function isLineInsideTestBlock(blocks: BlockRange[], line: number): boolean {
  return blocks.some((b) => line >= b.start && line <= b.end);
}

// ─── Severity downgrade helper ─────────────────────────────────

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function downgradeSeverity(s: Severity, levels = 1): Severity {
  const idx = SEVERITY_ORDER.indexOf(s);
  return SEVERITY_ORDER[Math.min(SEVERITY_ORDER.length - 1, idx + levels)];
}

// ─── Per-rule context filters ──────────────────────────────────

interface RuleFilter {
  ruleIds: string[];
  description: string;
  /** Return true to drop, "downgrade" to lower severity, false to keep as-is */
  evaluate(finding: Finding, content: string): true | false | "downgrade";
}

const RULE_FILTERS: RuleFilter[] = [
  {
    ruleIds: ["E2E-003", "E2E-004"],
    description: "Ratchet call wrapped in withSessionLock/withMutex (lambda scope)",
    evaluate(finding, content) {
      const lines = content.split("\n");
      const start = Math.max(0, finding.line - 30);
      const end = Math.min(lines.length, finding.line + 5);
      const window = lines.slice(start, end).join("\n");
      // Look for synchronization wrappers commonly used around ratchet ops
      if (/withSessionLock\b|withMutex\b|sync\.Mutex|RwLock::write|\.lock\(\)\?/.test(window)) {
        return "downgrade";
      }
      return false;
    },
  },
  {
    ruleIds: ["MSG-001"],
    description: "Generic notification template string, no real content",
    evaluate(finding) {
      const generic = /["'](new notification|you have a (new )?(encrypted )?message|new message|encrypted message|incoming call)["']/i;
      return generic.test(finding.snippet);
    },
  },
  {
    ruleIds: ["MSG-007"],
    description: "Logging .len()/byte count is metadata, not content",
    evaluate(finding) {
      const s = finding.snippet;
      // Logging a length/size value is fine — we only care about logging actual bytes
      if (/\.len\s*\(\s*\)|size_of_val|bytes\.length|\.size\b/.test(s)) {
        // But if same line ALSO logs the body, still keep
        if (/\b(body|payload|content|plaintext|ciphertext)\b\s*[,)]/i.test(s)) return false;
        return true;
      }
      return false;
    },
  },
  {
    ruleIds: ["AND-001"],
    description: "Activity exported because it has LAUNCHER intent-filter (required by Android)",
    evaluate(finding, content) {
      const lines = content.split("\n");
      // Look at +/-15 lines around finding for LAUNCHER category
      const start = Math.max(0, finding.line - 15);
      const end = Math.min(lines.length, finding.line + 15);
      for (let i = start; i < end; i++) {
        if (/android\.intent\.category\.LAUNCHER/.test(lines[i])) return true;
      }
      return false;
    },
  },
  {
    ruleIds: ["SRV-004"],
    description: "Axum/Actix extractor handler — auth applied per-request via type",
    evaluate(_finding, content) {
      // If the file uses extractor pattern (AuthUser, Extension, etc), public routes are intentional
      const hasExtractor = /\bAuthUser\s*\(/.test(content)
        || /\bExtension<.*User.*>/.test(content)
        || /from_request_parts/.test(content);
      return hasExtractor;
    },
  },
];

function findRuleFilter(ruleId: string): RuleFilter | undefined {
  return RULE_FILTERS.find((rf) => rf.ruleIds.includes(ruleId));
}

// ─── Main triage function ──────────────────────────────────────

export interface TriageDecision {
  ruleId: string;
  file: string;
  line: number;
  action: "drop" | "downgrade";
  reason: string;
  fromSeverity?: Severity;
  toSeverity?: Severity;
}

export interface TriageResult {
  kept: Finding[];
  dropped: TriageDecision[];
  downgraded: TriageDecision[];
}

export function triageFindings(findings: Finding[], projectDir: string): TriageResult {
  const kept: Finding[] = [];
  const dropped: TriageDecision[] = [];
  const downgraded: TriageDecision[] = [];

  // Cache file content + test block ranges per file
  const fileCache = new Map<string, { content: string | null; testBlocks: BlockRange[] }>();

  function getCacheEntry(relFile: string) {
    let entry = fileCache.get(relFile);
    if (entry) return entry;
    const abs = path.isAbsolute(relFile) ? relFile : path.join(projectDir, relFile);
    let content: string | null = null;
    let testBlocks: BlockRange[] = [];
    try {
      content = fs.readFileSync(abs, "utf-8");
      testBlocks = findTestBlocks(content);
    } catch {
      // file unreadable — leave content null
    }
    entry = { content, testBlocks };
    fileCache.set(relFile, entry);
    return entry;
  }

  for (const finding of findings) {
    // 1. Drop config files entirely
    if (isConfigFile(finding.file)) {
      dropped.push({
        ruleId: finding.ruleId,
        file: finding.file,
        line: finding.line,
        action: "drop",
        reason: "config file (legitimately committed by convention)",
      });
      continue;
    }

    // 2. Per-rule context filters
    // Always run the filter — pass empty string if file not readable so filters
    // that only inspect the snippet still fire.
    const filter = findRuleFilter(finding.ruleId);
    if (filter) {
      const content = getCacheEntry(finding.file).content ?? "";
      const decision = filter.evaluate(finding, content);
      if (decision === true) {
        dropped.push({
          ruleId: finding.ruleId,
          file: finding.file,
          line: finding.line,
          action: "drop",
          reason: filter.description,
        });
        continue;
      }
      if (decision === "downgrade") {
        const toSev = downgradeSeverity(finding.severity, 2);
        downgraded.push({
          ruleId: finding.ruleId,
          file: finding.file,
          line: finding.line,
          action: "downgrade",
          reason: filter.description,
          fromSeverity: finding.severity,
          toSeverity: toSev,
        });
        kept.push({ ...finding, severity: toSev });
        continue;
      }
    }

    // 3. Test paths → downgrade severity by 2 levels
    if (isTestPath(finding.file)) {
      const toSev = downgradeSeverity(finding.severity, 2);
      downgraded.push({
        ruleId: finding.ruleId,
        file: finding.file,
        line: finding.line,
        action: "downgrade",
        reason: "finding is in a test path",
        fromSeverity: finding.severity,
        toSeverity: toSev,
      });
      kept.push({ ...finding, severity: toSev });
      continue;
    }

    // 4. Inline test block (e.g., Rust #[cfg(test)] mod tests { ... }) → downgrade
    const { content, testBlocks } = getCacheEntry(finding.file);
    if (content !== null && isLineInsideTestBlock(testBlocks, finding.line)) {
      const toSev = downgradeSeverity(finding.severity, 2);
      downgraded.push({
        ruleId: finding.ruleId,
        file: finding.file,
        line: finding.line,
        action: "downgrade",
        reason: "finding is inside an inline test block (cfg(test) / mod tests)",
        fromSeverity: finding.severity,
        toSeverity: toSev,
      });
      kept.push({ ...finding, severity: toSev });
      continue;
    }

    kept.push(finding);
  }

  return { kept, dropped, downgraded };
}
