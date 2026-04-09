// AI-powered finding extraction from audit PDFs
// Uses Claude to understand ANY report format — not just regex patterns

import * as fs from "fs";
import Anthropic from "@anthropic-ai/sdk";
import { ExtractedFinding, ReportInfo } from "./extractor.js";
import { SecurityAuditDB, modelSlug, type FindingInsert } from "./db.js";

const CHUNK_SIZE = 50_000;
const CHUNK_OVERLAP = 1_000;
const MAX_OUTPUT_TOKENS = 8192;
const RATE_LIMIT_DELAY_MS = 5_000;

const MODEL_COSTS: Record<string, { input: number; output: number }> = {
  opus: { input: 15, output: 75 },
  sonnet: { input: 3, output: 15 },
  haiku: { input: 0.25, output: 1.25 },
};

/** Token usage from a single API call */
interface ChunkResult {
  findings: ExtractedFinding[];
  input_tokens: number;
  output_tokens: number;
}

/** Split PDF text into chunks that fit in context window */
function chunkText(text: string, maxChars: number = CHUNK_SIZE): string[] {
  if (text.length <= maxChars) return [text];
  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    chunks.push(text.substring(start, start + maxChars));
    start += maxChars - CHUNK_OVERLAP; // overlap for context
  }
  return chunks;
}

/** Extract findings from a single PDF text chunk using Claude */
async function extractChunk(
  client: Anthropic,
  text: string,
  source: ReportInfo,
  model: string,
): Promise<ChunkResult> {
  const response = await client.messages.create({
    model,
    max_tokens: MAX_OUTPUT_TOKENS,
    system: `You are a security audit report parser. Extract ALL security findings/vulnerabilities from the given audit report text.

For EACH finding, output a JSON object with:
- severity: "critical" | "high" | "medium" | "low" | "info"
- title: short title of the finding
- description: 1-2 sentence description of the vulnerability
- category: one of: "Cryptography", "Authentication", "Memory Safety", "Input Validation", "Key Management", "Data Storage", "Server Security", "Mobile Security", "Configuration", "Information Disclosure", "E2E Protocol", "WebRTC/P2P", "Denial of Service", "Smart Contracts", "Metadata/Side Channel", "Message Integrity", "Group Security", "Notifications", "General"
- cwe: CWE ID if mentioned (e.g. "CWE-79"), or null

Rules:
- Extract EVERY finding, not just critical ones
- Include informational findings too
- If severity is not explicit, infer from context (e.g. "recommendation" = info, "vulnerability" with exploit = high)
- For academic papers, extract each described attack/vulnerability as a finding
- Respond ONLY with a JSON array. No other text.
- If no findings found, respond with []`,
    messages: [{
      role: "user",
      content: `Audit report from ${source.firm} reviewing ${source.target}:\n\n${text}`
    }],
  });

  const input_tokens = response.usage?.input_tokens ?? 0;
  const output_tokens = response.usage?.output_tokens ?? 0;

  const responseText = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  const jsonMatch = responseText.match(/\[[\s\S]*\]/);
  if (!jsonMatch) return { findings: [], input_tokens, output_tokens };

  try {
    const raw = JSON.parse(jsonMatch[0]) as any[];
    const findings = raw.map((f) => ({
      sourceId: source.id,
      firm: source.firm,
      target: source.target,
      severity: f.severity || "info",
      title: f.title || "Unknown",
      description: f.description || "",
      category: f.category || "General",
      cwe: f.cwe || undefined,
    }));
    return { findings, input_tokens, output_tokens };
  } catch (error) {
    console.error(`[sentinel-kb] Failed to parse chunk JSON: ${error instanceof Error ? error.message : error}`);
    return { findings: [], input_tokens, output_tokens };
  }
}

/** Cost per 1M tokens by model family */
function estimateCost(model: string, inputTokens: number, outputTokens: number): number {
  const slug = modelSlug(model);
  const costs = MODEL_COSTS[slug] ?? MODEL_COSTS.sonnet;
  return (inputTokens * costs.input + outputTokens * costs.output) / 1_000_000;
}

/** AI-extract findings from a single PDF file, writing results to DB */
export async function aiExtractFromPdf(
  pdfPath: string,
  source: ReportInfo,
  client: Anthropic,
  db: SecurityAuditDB,
  model: string = "claude-sonnet-4-20250514",
): Promise<{ findings: ExtractedFinding[]; input_tokens: number; output_tokens: number }> {
  const slug = modelSlug(model);

  // Check DB cache
  if (db.isExtracted(source.id, slug)) {
    const rows = db.getFindingsForReport(source.id);
    return { findings: db.toExtractedFindings(rows), input_tokens: 0, output_tokens: 0 };
  }

  // Parse PDF
  const pdfModule = await import("pdf-parse");
  const PDFParse = (pdfModule as any).PDFParse;
  const buffer = new Uint8Array(fs.readFileSync(pdfPath));
  const parser = new PDFParse(buffer);
  await parser.load();
  const result = await parser.getText();

  const startTime = Date.now();
  const extractionId = db.beginExtraction(source.id, model, slug, "ai");

  if (!result.text || result.text.length < 100) {
    db.completeExtraction(extractionId, 0, { duration_ms: Date.now() - startTime });
    return { findings: [], input_tokens: 0, output_tokens: 0 };
  }

  // Chunk and extract
  const chunks = chunkText(result.text);
  const allFindings: ExtractedFinding[] = [];
  let totalInput = 0;
  let totalOutput = 0;

  for (const chunk of chunks) {
    try {
      const chunkResult = await extractChunk(client, chunk, source, model);
      allFindings.push(...chunkResult.findings);
      totalInput += chunkResult.input_tokens;
      totalOutput += chunkResult.output_tokens;
    } catch (err: any) {
      if (err.message?.includes("rate") || err.status === 429) {
        await new Promise((r) => setTimeout(r, RATE_LIMIT_DELAY_MS));
        try {
          const chunkResult = await extractChunk(client, chunk, source, model);
          allFindings.push(...chunkResult.findings);
          totalInput += chunkResult.input_tokens;
          totalOutput += chunkResult.output_tokens;
        } catch (retryError) {
          console.error(`[sentinel-kb] Failed to extract chunk after retry: ${retryError instanceof Error ? retryError.message : retryError}`);
        }
      }
    }
  }

  // Dedup by title
  const seen = new Set<string>();
  const deduped = allFindings.filter((f) => {
    const key = f.title.toLowerCase().trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Write to DB
  const findingInserts: FindingInsert[] = deduped.map((f) => ({
    report_id: source.id,
    extraction_id: extractionId,
    severity: f.severity,
    title: f.title,
    description: f.description,
    category: f.category,
    cwe: f.cwe,
  }));
  db.insertFindings(findingInserts);

  const durationMs = Date.now() - startTime;
  const cost = estimateCost(model, totalInput, totalOutput);
  db.completeExtraction(extractionId, deduped.length, {
    input_tokens: totalInput,
    output_tokens: totalOutput,
    cost_usd: cost,
    duration_ms: durationMs,
  });

  return { findings: deduped, input_tokens: totalInput, output_tokens: totalOutput };
}

/** AI-extract findings from all downloaded PDFs */
export async function aiExtractAll(
  reports: { source: ReportInfo; path: string }[],
  apiKey: string,
  db: SecurityAuditDB,
  model: string = "claude-sonnet-4-20250514",
  concurrency: number = 3,
): Promise<{
  findings: ExtractedFinding[];
  errors: { id: string; error: string }[];
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCost: number;
}> {
  const client = new Anthropic({ apiKey });
  const slug = modelSlug(model);
  const allFindings: ExtractedFinding[] = [];
  const errors: { id: string; error: string }[] = [];

  let cached = 0;
  let extracted = 0;
  let failed = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;

  // Start model run
  const runId = db.beginModelRun(model, slug, "extraction");
  const runStart = Date.now();

  // Process in batches for rate limit management
  for (let i = 0; i < reports.length; i += concurrency) {
    const batch = reports.slice(i, i + concurrency);
    const results = await Promise.allSettled(
      batch.map(async (report) => {
        // Ensure report exists in DB
        db.upsertReport({
          id: report.source.id,
          firm: report.source.firm,
          target: report.source.target,
          download_status: "downloaded",
        });

        if (db.isExtracted(report.source.id, slug)) {
          const rows = db.getFindingsForReport(report.source.id);
          cached++;
          allFindings.push(...db.toExtractedFindings(rows));
          return;
        }

        const result = await aiExtractFromPdf(report.path, report.source, client, db, model);
        allFindings.push(...result.findings);
        totalInputTokens += result.input_tokens;
        totalOutputTokens += result.output_tokens;
        extracted++;
        if (result.findings.length > 0) {
          console.log(`  \u2713 ${report.source.id}: ${result.findings.length} findings`);
        }
      })
    );

    for (let j = 0; j < results.length; j++) {
      if (results[j].status === "rejected") {
        const report = batch[j];
        const err = (results[j] as PromiseRejectedResult).reason;
        errors.push({ id: report.source.id, error: err?.message || "Unknown error" });
        failed++;
      }
    }

    // Progress
    const done = Math.min(i + concurrency, reports.length);
    const cost = estimateCost(model, totalInputTokens, totalOutputTokens);
    process.stdout.write(
      `\r  Progress: ${done}/${reports.length} (${extracted} new, ${cached} cached, ${failed} failed) $${cost.toFixed(3)}`
    );

    // Brief pause between batches for rate limits
    if (i + concurrency < reports.length && extracted > 0) {
      await new Promise((r) => setTimeout(r, 500));
    }
  }

  console.log();

  // Complete model run
  const totalCost = estimateCost(model, totalInputTokens, totalOutputTokens);
  db.completeModelRun(runId, {
    reports_processed: extracted + cached,
    findings_total: allFindings.length,
    input_tokens: totalInputTokens,
    output_tokens: totalOutputTokens,
    cost_usd: totalCost,
    duration_ms: Date.now() - runStart,
  });

  return { findings: allFindings, errors, totalInputTokens, totalOutputTokens, totalCost };
}
