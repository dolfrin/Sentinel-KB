// sentinel-kb-ignore-file
// AI triage layer — uses Claude + KB context to judge each finding's real-world impact.
// Runs after path-based triage (triage.ts) and Semgrep (semgrep.ts).
//
// Cost: ~$0.005 per finding with claude-sonnet (5-15 findings per request, batched).
// Requires ANTHROPIC_API_KEY. Falls back gracefully if missing or on errors.

import * as fs from "fs";
import * as path from "path";
import Anthropic from "@anthropic-ai/sdk";
import { z } from "zod";
import type { Finding } from "./scanner.js";
import type { Severity } from "./rules.js";
import { getDB } from "./db.js";

// ─── Types ─────────────────────────────────────────────────────

export interface AITriageOptions {
  /** API key — falls back to ANTHROPIC_API_KEY env */
  apiKey?: string;
  /** Model to use — default claude-sonnet-4-6 */
  model?: string;
  /** Min confidence (0-100) to keep a finding — default 60 */
  minConfidence?: number;
  /** Findings per Claude request — default 8 */
  batchSize?: number;
  /** Max code context lines around each finding — default 30 */
  contextLines?: number;
  /** KB matches per finding — default 3 */
  kbMatchesPerFinding?: number;
}

export interface AITriageVerdict {
  ruleId: string;
  file: string;
  line: number;
  isReal: boolean;
  confidence: number;       // 0-100
  reasoning: string;
  similarKbFinding?: string;  // ID of most relevant KB match (if any)
}

export interface AITriageResult {
  /** Findings that survived triage (isReal && confidence >= minConfidence) */
  kept: Finding[];
  /** Findings dropped as false positives, with Claude's reasoning */
  rejected: AITriageVerdict[];
  /** All verdicts (kept + rejected) for transparency */
  verdicts: AITriageVerdict[];
  /** Whether AI triage actually ran (false if no API key or no findings) */
  ran: boolean;
  /** Estimated cost in USD */
  costUsd: number;
  /** Error message if AI triage failed */
  error?: string;
}

// ─── Schemas ───────────────────────────────────────────────────

const VerdictSchema = z.object({
  index: z.number().int().nonnegative(),
  isReal: z.boolean(),
  confidence: z.number().min(0).max(100),
  reasoning: z.string().min(1),
  similarKbFinding: z.string().optional(),
});

// Pricing per 1M tokens (Sonnet 4.6 — adjust as Anthropic updates)
const SONNET_INPUT_PER_MTOK = 3.0;
const SONNET_OUTPUT_PER_MTOK = 15.0;

// ─── Code context extraction ───────────────────────────────────

interface CodeContext {
  file: string;
  line: number;
  snippet: string;
}

function extractContext(
  projectDir: string,
  finding: Finding,
  contextLines: number,
  fileCache: Map<string, string | null>
): CodeContext {
  let content = fileCache.get(finding.file);
  if (content === undefined) {
    const abs = path.isAbsolute(finding.file) ? finding.file : path.join(projectDir, finding.file);
    try {
      content = fs.readFileSync(abs, "utf-8");
    } catch {
      content = null;
    }
    fileCache.set(finding.file, content);
  }
  if (content === null) {
    return { file: finding.file, line: finding.line, snippet: finding.snippet };
  }
  const lines = content.split("\n");
  const start = Math.max(0, finding.line - contextLines - 1);
  const end = Math.min(lines.length, finding.line + contextLines);
  const numbered = lines.slice(start, end).map((l, i) => {
    const ln = start + i + 1;
    const marker = ln === finding.line ? ">>>" : "   ";
    return `${marker} ${ln.toString().padStart(4, " ")}: ${l}`;
  });
  return { file: finding.file, line: finding.line, snippet: numbered.join("\n") };
}

// ─── KB context lookup ─────────────────────────────────────────

function kbContextFor(finding: Finding, limit: number): string[] {
  try {
    const db = getDB();
    const query = `${finding.category} ${finding.message}`.replace(/[^a-zA-Z0-9 ]/g, " ").slice(0, 200);
    const rows = db.searchFindingsByCategory(query, [finding.category], limit);
    if (rows.length === 0) {
      // Fall back to plain search
      const fallback = db.searchFindings(query, limit);
      return fallback.map((r) => `[${r.id}] ${r.firm} → ${r.target}: ${r.title}`);
    }
    return rows.map((r) => `[${r.id}] ${r.firm} → ${r.target}: ${r.title}`);
  } catch {
    return [];
  }
}

// ─── Prompt builder ────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior security auditor reviewing static analysis findings to filter false positives.

For each finding, decide:
1. isReal — is this a genuine vulnerability in this specific code context, or a false positive?
2. confidence — your confidence in that judgment, 0-100.
3. reasoning — one sentence explaining why.
4. similarKbFinding — if a knowledge-base entry matches this pattern closely, cite its ID.

Be skeptical of regex-based findings. Common false positive patterns:
- Code in test files / fixtures / mocks (intentionally insecure for testing)
- Generic strings / template placeholders mistaken for secrets
- Required platform exports (Android LAUNCHER, iOS Info.plist)
- Auth applied via type-system (Axum extractors, NestJS guards)
- Synchronization wrappers around critical sections (withMutex, withSessionLock)
- Logging only metadata (length, count) rather than content

Respond with JSON only — an array of verdicts in finding-index order.`;

interface FindingPromptInput {
  index: number;
  finding: Finding;
  context: CodeContext;
  kbMatches: string[];
}

function buildUserPrompt(batch: FindingPromptInput[]): string {
  const parts: string[] = [];
  parts.push(`Review the following ${batch.length} static analysis findings. For each, judge if it's a real vulnerability in context.`);
  parts.push("");
  parts.push("Respond with JSON array only:");
  parts.push("[");
  parts.push(`  {"index": 0, "isReal": true|false, "confidence": 0-100, "reasoning": "...", "similarKbFinding": "id-if-any"},`);
  parts.push("  ...");
  parts.push("]");
  parts.push("");

  for (const item of batch) {
    parts.push(`────── Finding ${item.index} ──────`);
    parts.push(`Rule: [${item.finding.ruleId}] ${item.finding.ruleName}`);
    parts.push(`Severity (static): ${item.finding.severity}`);
    parts.push(`Category: ${item.finding.category}`);
    parts.push(`Message: ${item.finding.message}`);
    parts.push(`Location: ${item.context.file}:${item.context.line}`);
    parts.push("");
    parts.push("Code context:");
    parts.push(item.context.snippet);
    parts.push("");
    if (item.kbMatches.length > 0) {
      parts.push("Similar findings from knowledge base:");
      for (const m of item.kbMatches) parts.push(`  - ${m}`);
      parts.push("");
    }
  }
  return parts.join("\n");
}

// ─── Response parsing ──────────────────────────────────────────

function parseVerdicts(raw: string, batchSize: number): z.infer<typeof VerdictSchema>[] {
  // Strip markdown code fences if Claude wraps the JSON
  let text = raw.trim();
  const fence = text.match(/```(?:json)?\s*([\s\S]+?)```/);
  if (fence) text = fence[1].trim();

  // Find the JSON array
  const arrayStart = text.indexOf("[");
  const arrayEnd = text.lastIndexOf("]");
  if (arrayStart === -1 || arrayEnd === -1 || arrayEnd <= arrayStart) {
    throw new Error("No JSON array in response");
  }
  text = text.slice(arrayStart, arrayEnd + 1);

  const parsed = JSON.parse(text);
  if (!Array.isArray(parsed)) throw new Error("Response is not an array");

  const verdicts: z.infer<typeof VerdictSchema>[] = [];
  for (const item of parsed) {
    const result = VerdictSchema.safeParse(item);
    if (result.success) verdicts.push(result.data);
  }
  if (verdicts.length === 0) throw new Error("No valid verdicts parsed");
  return verdicts;
}

// ─── Main triage runner ────────────────────────────────────────

export async function aiTriageFindings(
  findings: Finding[],
  projectDir: string,
  options?: AITriageOptions
): Promise<AITriageResult> {
  const apiKey = options?.apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { kept: findings, rejected: [], verdicts: [], ran: false, costUsd: 0, error: "no API key" };
  }
  if (findings.length === 0) {
    return { kept: [], rejected: [], verdicts: [], ran: false, costUsd: 0 };
  }

  const model = options?.model ?? "claude-sonnet-4-6";
  const minConfidence = options?.minConfidence ?? 60;
  const batchSize = options?.batchSize ?? 8;
  const contextLines = options?.contextLines ?? 30;
  const kbLimit = options?.kbMatchesPerFinding ?? 3;

  const client = new Anthropic({ apiKey });
  const fileCache = new Map<string, string | null>();
  const verdicts: AITriageVerdict[] = [];
  let totalCost = 0;
  let firstError: string | undefined;

  // Prepare batches
  for (let batchStart = 0; batchStart < findings.length; batchStart += batchSize) {
    const batch = findings.slice(batchStart, batchStart + batchSize);
    const promptInputs: FindingPromptInput[] = batch.map((finding, i) => ({
      index: i,
      finding,
      context: extractContext(projectDir, finding, contextLines, fileCache),
      kbMatches: kbContextFor(finding, kbLimit),
    }));

    try {
      const response = await client.messages.create({
        model,
        max_tokens: 4000,
        system: SYSTEM_PROMPT,
        messages: [{ role: "user", content: buildUserPrompt(promptInputs) }],
      });

      // Track cost
      const inTok = response.usage.input_tokens;
      const outTok = response.usage.output_tokens;
      totalCost += (inTok / 1_000_000) * SONNET_INPUT_PER_MTOK + (outTok / 1_000_000) * SONNET_OUTPUT_PER_MTOK;

      const textBlock = response.content.find((b) => b.type === "text");
      if (!textBlock || textBlock.type !== "text") {
        if (!firstError) firstError = "Claude returned no text";
        // Default-keep on parse failure (conservative)
        for (let i = 0; i < batch.length; i++) {
          verdicts.push({
            ruleId: batch[i].ruleId,
            file: batch[i].file,
            line: batch[i].line,
            isReal: true,
            confidence: 50,
            reasoning: "AI triage failed — kept as-is",
          });
        }
        continue;
      }

      let parsed: z.infer<typeof VerdictSchema>[];
      try {
        parsed = parseVerdicts(textBlock.text, batch.length);
      } catch (e: any) {
        if (!firstError) firstError = `Parse error: ${e.message}`;
        for (let i = 0; i < batch.length; i++) {
          verdicts.push({
            ruleId: batch[i].ruleId,
            file: batch[i].file,
            line: batch[i].line,
            isReal: true,
            confidence: 50,
            reasoning: "AI triage failed — kept as-is",
          });
        }
        continue;
      }

      // Map verdicts back to findings by index
      const verdictByIndex = new Map<number, z.infer<typeof VerdictSchema>>();
      for (const v of parsed) verdictByIndex.set(v.index, v);

      for (let i = 0; i < batch.length; i++) {
        const finding = batch[i];
        const v = verdictByIndex.get(i);
        if (v) {
          verdicts.push({
            ruleId: finding.ruleId,
            file: finding.file,
            line: finding.line,
            isReal: v.isReal,
            confidence: v.confidence,
            reasoning: v.reasoning,
            similarKbFinding: v.similarKbFinding,
          });
        } else {
          // Missing verdict for this finding — default keep
          verdicts.push({
            ruleId: finding.ruleId,
            file: finding.file,
            line: finding.line,
            isReal: true,
            confidence: 50,
            reasoning: "no verdict returned — kept as-is",
          });
        }
      }
    } catch (e: any) {
      if (!firstError) firstError = e.message;
      // Network/API failure — default keep
      for (let i = 0; i < batch.length; i++) {
        verdicts.push({
          ruleId: batch[i].ruleId,
          file: batch[i].file,
          line: batch[i].line,
          isReal: true,
          confidence: 50,
          reasoning: `AI triage error: ${e.message}`,
        });
      }
    }
  }

  // Apply verdicts
  const kept: Finding[] = [];
  const rejected: AITriageVerdict[] = [];
  for (let i = 0; i < findings.length; i++) {
    const v = verdicts[i];
    if (!v) {
      kept.push(findings[i]);
      continue;
    }
    if (v.isReal && v.confidence >= minConfidence) {
      kept.push(findings[i]);
    } else {
      rejected.push(v);
    }
  }

  return {
    kept,
    rejected,
    verdicts,
    ran: true,
    costUsd: Number(totalCost.toFixed(6)),
    error: firstError,
  };
}

// ─── Severity recalibration based on AI confidence ─────────────

/**
 * Recalibrate finding severity based on AI confidence.
 * High confidence keeps original severity; low confidence downgrades.
 */
export function recalibrateSeverity(
  findings: Finding[],
  verdicts: AITriageVerdict[]
): Finding[] {
  const verdictMap = new Map<string, AITriageVerdict>();
  for (const v of verdicts) verdictMap.set(`${v.ruleId}:${v.file}:${v.line}`, v);

  const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

  return findings.map((f) => {
    const v = verdictMap.get(`${f.ruleId}:${f.file}:${f.line}`);
    if (!v) return f;
    if (v.confidence >= 85) return f;       // strong AI confirmation
    if (v.confidence >= 70) return f;       // moderate
    if (v.confidence >= 50) {                // weak — downgrade by 1
      const idx = SEV_ORDER.indexOf(f.severity);
      return { ...f, severity: SEV_ORDER[Math.min(SEV_ORDER.length - 1, idx + 1)] };
    }
    // Below 50 — should have been rejected, but defensively downgrade by 2
    const idx = SEV_ORDER.indexOf(f.severity);
    return { ...f, severity: SEV_ORDER[Math.min(SEV_ORDER.length - 1, idx + 2)] };
  });
}
