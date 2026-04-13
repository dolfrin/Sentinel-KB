#!/usr/bin/env node

// Full pipeline: crawl all sources -> fetch PDFs -> parse -> extract findings -> knowledge base (SQLite)

import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import * as http from "http";
import { discoverAll, DiscoveredReport } from "./crawler.js";
import { extractFromPdf, ExtractedFinding, ReportInfo } from "./extractor.js";
import { aiExtractAll } from "./ai-extractor.js";
import { getDB, closeDB } from "./db.js";

const BASE_DIR = path.join(process.env.HOME || "~", ".security-audit-kb");
const REPORTS_DIR = path.join(BASE_DIR, "reports");
const FINDINGS_PATH = path.join(BASE_DIR, "knowledge-base.json");

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

/** Download a PDF, validating it's actually a PDF */
function downloadPdf(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    ensureDir(path.dirname(dest));

    const doRequest = (currentUrl: string, depth: number) => {
      if (depth > 10) { reject(new Error("Too many redirects")); return; }
      const c = currentUrl.startsWith("https") ? https : http;
      c.get(currentUrl, { headers: { "User-Agent": "security-audit-kb/0.1" } }, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          const loc = res.headers.location;
          try {
            doRequest(loc.startsWith("http") ? loc : new URL(loc, currentUrl).href, depth + 1);
          } catch (err) {
            reject(err);
          }
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        const ct = res.headers["content-type"] || "";
        if (ct.includes("text/html")) {
          res.resume();
          reject(new Error("HTML instead of PDF"));
          return;
        }

        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => {
          file.close();
          const stats = fs.statSync(dest);
          if (stats.size < 1000) {
            fs.unlinkSync(dest);
            reject(new Error("File too small"));
          } else {
            resolve();
          }
        });
      }).on("error", (err) => {
        fs.rmSync(dest, { force: true });
        reject(err);
      });
    };

    doRequest(url, 0);
  });
}

function reportPath(report: DiscoveredReport): string {
  return path.join(REPORTS_DIR, `${report.id}.pdf`);
}

function isValidPdf(filePath: string): boolean {
  if (!fs.existsSync(filePath)) return false;
  const stats = fs.statSync(filePath);
  if (stats.size < 1000) return false;
  const fd = fs.openSync(filePath, "r");
  const buf = Buffer.alloc(5);
  fs.readSync(fd, buf, 0, 5, 0);
  fs.closeSync(fd);
  return buf.toString() === "%PDF-";
}

async function main() {
  const db = getDB();

  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
  console.log("  SECURITY AUDIT \u2014 Knowledge Base Update");
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");

  // Handle --migrate: import existing JSON into SQLite
  if (process.argv.includes("--migrate")) {
    console.log("\n\u2500\u2500 Migrating existing data to SQLite \u2500\u2500\n");

    // Import from knowledge-base.json
    // importFromJson handles missing files gracefully
    const jsonResult = db.importFromJson(FINDINGS_PATH, "regex");
    if (jsonResult.findings > 0) {
      console.log(`  Importing ${FINDINGS_PATH}...`);
      console.log(`  \u2713 JSON: ${jsonResult.reports} reports, ${jsonResult.findings} findings`);
    }

    // Import from per-model cache
    const cacheDir = path.join(BASE_DIR, "extracted");
    // importFromCache handles missing dir gracefully
    const cacheResult = db.importFromCache(cacheDir);
    if (cacheResult.findings > 0) {
      console.log(`  Importing cache from ${cacheDir}...`);
      console.log(`  \u2713 Cache: ${cacheResult.models.join(", ")} \u2014 ${cacheResult.reports} reports, ${cacheResult.findings} findings`);
    }

    const stats = db.getStats();
    console.log(`\n  Database: ${stats.total_findings} findings, ${stats.total_reports} reports, ${stats.total_firms} firms`);
    closeDB();
    return;
  }

  // Handle --stats: show DB stats
  if (process.argv.includes("--stats")) {
    const stats = db.getStats();
    console.log(`\n  Findings: ${stats.total_findings}`);
    console.log(`  Reports:  ${stats.total_reports}`);
    console.log(`  Firms:    ${stats.total_firms}`);
    console.log(`  Canonical: ${stats.canonical_count}`);

    console.log("\n  By severity:");
    for (const [sev, n] of Object.entries(stats.by_severity)) {
      console.log(`    ${sev}: ${n}`);
    }

    console.log("\n  By model:");
    for (const [model, data] of Object.entries(stats.by_model)) {
      console.log(`    ${model}: ${data.reports} reports, ${data.findings} findings, $${data.cost_usd.toFixed(3)}`);
    }

    console.log("\n  Top categories:");
    for (const [cat, n] of Object.entries(stats.by_category).slice(0, 10)) {
      console.log(`    ${cat}: ${n}`);
    }

    console.log("\n  Top firms:");
    for (const [firm, n] of Object.entries(stats.by_firm).slice(0, 15)) {
      console.log(`    ${firm}: ${n}`);
    }

    closeDB();
    return;
  }

  // ── Step 1: Discover all available reports ──
  console.log("\n\u2500\u2500 Step 1: Discovering audit reports \u2500\u2500");
  const reports = await discoverAll();
  console.log(`  Total discoverable: ${reports.length} reports\n`);

  // Register all discovered reports in DB
  for (const r of reports) {
    db.upsertReport({
      id: r.id,
      firm: r.firm,
      target: r.target,
      url: r.url,
      download_status: isValidPdf(reportPath(r)) ? "downloaded" : "pending",
    });
  }

  // ── Step 2: Download reports we don't have ──
  console.log("\u2500\u2500 Step 2: Downloading new reports \u2500\u2500\n");
  let downloaded = 0;
  let skipped = 0;
  let dlFailed = 0;

  const BATCH_SIZE = 10;
  for (let i = 0; i < reports.length; i += BATCH_SIZE) {
    const batch = reports.slice(i, i + BATCH_SIZE);
    await Promise.allSettled(
      batch.map(async (report) => {
        const dest = reportPath(report);
        if (isValidPdf(dest)) {
          skipped++;
          db.updateDownloadStatus(report.id, "downloaded", { pdfPath: dest });
          return;
        }
        fs.rmSync(dest, { force: true });
        try {
          await downloadPdf(report.url, dest);
          downloaded++;
          db.updateDownloadStatus(report.id, "downloaded", { pdfPath: dest });
        } catch (err: any) {
          dlFailed++;
          db.updateDownloadStatus(report.id, "failed", { error: err.message });
        }
      })
    );

    const total = Math.min(i + BATCH_SIZE, reports.length);
    process.stdout.write(`\r  Progress: ${total}/${reports.length} (${downloaded} new, ${skipped} cached, ${dlFailed} failed)`);
  }
  console.log(`\n  Done: ${downloaded} downloaded, ${skipped} cached, ${dlFailed} failed\n`);

  // ── Step 3: Extract findings ──
  const useAI = !process.argv.includes("--regex") && !!process.env.ANTHROPIC_API_KEY;
  console.log(`\u2500\u2500 Step 3: Extracting findings (${useAI ? "AI" : "regex"} mode) \u2500\u2500\n`);

  // Build valid reports list (discovered + cached PDFs)
  const validReports = reports
    .filter((r) => isValidPdf(reportPath(r)))
    .map((r) => ({
      source: { id: r.id, firm: r.firm, target: r.target } as ReportInfo,
      path: reportPath(r),
    }));

  // Include cached PDFs from previous runs
  const knownPaths = new Set(validReports.map((r) => r.path));
  let cachedFiles: string[];
  try {
    cachedFiles = fs.readdirSync(REPORTS_DIR).filter((f) => f.endsWith(".pdf"));
  } catch {
    cachedFiles = [];
  }
  {
    const cached = cachedFiles;
    for (const filename of cached) {
      const fullPath = path.join(REPORTS_DIR, filename);
      if (knownPaths.has(fullPath)) continue;
      if (!isValidPdf(fullPath)) continue;
      const id = filename.replace(/\.pdf$/, "");
      const firmMap: Record<string, string> = {
        "7asecurity": "7ASecurity", "adalogics": "ADALogics", "atredis": "Atredis",
        "bishop-fox": "Bishop Fox", "bugcrowd": "Bugcrowd", "certik": "CertiK",
        "coinspect": "Coinspect", "consensys": "Consensys", "cure53": "Cure53",
        "doyensec": "Doyensec", "enable-security": "Enable Security",
        "fireye": "FireEye", "fox-it": "Fox-IT", "fraunhofer": "Fraunhofer",
        "hacken": "Hacken", "hackmanit": "Hackmanit", "ioactive": "IOActive",
        "includesecurity": "Include Security", "ise": "Independent Security Evaluators",
        "kudelski": "Kudelski Security", "leastauthority": "Least Authority",
        "leviathan": "Leviathan", "mitre": "MITRE", "matasano": "Matasano",
        "nccgroup": "NCC Group", "ncc-group": "NCC Group",
        "nettitude": "Nettitude", "openwall": "Openwall",
        "paragon": "Paragon Initiative", "pwc": "PwC",
        "quarkslab": "QuarksLab", "radicallyopensecurity": "Radically Open Security",
        "randorisec": "Randorisec", "recuritylabs": "Recurity Labs",
        "red4sec": "Red4Sec", "secconsult": "SEC Consult",
        "securideas": "Secure Ideas", "securitum": "Securitum",
        "shieldsec": "ShielderSec", "tob": "Trail of Bits",
        "trailofbits": "Trail of Bits", "trustfoundry": "TrustFoundry",
        "veracode": "Veracode", "verizon": "Verizon",
        "x41": "X41 D-Sec", "isec": "iSEC Partners", "mnemonic": "mnemonic",
        "fireeye": "FireEye", "nasa": "NASA OIG", "opm": "OPM OIG",
        "national": "NCATS", "logicaltrust": "LogicalTrust",
        "fh-munster": "FH M\u00fcnster", "primoconnect": "PrimoConnect",
        "blazeinformation": "Blaze Information Security",
        "procheckup": "ProCheckUp", "cryptography": "Cryptography Research",
        "secfaultsecurity": "Secfault Security",
        "securing": "SecuRing", "secura": "Secura",
        "securusglobal": "SecurusGlobal", "shieldersec": "ShielderSec",
        "sixgen": "Sixgen", "swisscert": "SwissCERT", "tcm": "TCM Security",
        "underdefense": "UnderDefense", "voidsec": "VoidSec", "volkis": "Volkis",
        "red-siege": "Red Siege", "offensive": "Offensive Security",
        "pentest-limited": "Pentest Limited", "princeton": "Princeton University",
        "cptc": "CPTC", "comsats": "COMSATS",
        "cynergi": "Cynergi Solutions", "defuse": "Defuse Security",
        "falanx": "Falanx Cyber Defence", "fticonsulting": "FTI Consulting",
        "os3": "OS3", "sakurity": "Sakurity", "spoc": "SPoC",
      };
      let firm = "Unknown";
      for (const [prefix, name] of Object.entries(firmMap)) {
        if (id.startsWith(prefix)) { firm = name; break; }
      }
      const source = { id, firm, target: id.replace(/[-_]/g, " ") } as ReportInfo;
      db.upsertReport({ ...source, download_status: "downloaded" });
      validReports.push({ source, path: fullPath });
    }
  }

  // Filter out reports already extracted with this method
  const methodSlug = useAI
    ? (process.argv.includes("--ai-model")
        ? process.argv[process.argv.indexOf("--ai-model") + 1]
        : "sonnet")
    : "regex";
  const newReports = validReports.filter((r) => !db.isExtracted(r.source.id, methodSlug));
  const skippedExtraction = validReports.length - newReports.length;

  console.log(`  Total valid PDFs: ${validReports.length} (${skippedExtraction} already extracted, ${newReports.length} new)\n`);

  let allFindings: ExtractedFinding[];
  let parseErrors: number;

  if (newReports.length === 0) {
    console.log("  Nothing new to extract — skipping.\n");
    allFindings = [];
    parseErrors = 0;
  } else if (useAI) {
    const apiKey = process.env.ANTHROPIC_API_KEY!;
    const aiModel = process.argv.includes("--ai-model")
      ? process.argv[process.argv.indexOf("--ai-model") + 1]
      : "claude-sonnet-4-20250514";
    const concurrency = process.argv.includes("--concurrency")
      ? parseInt(process.argv[process.argv.indexOf("--concurrency") + 1])
      : 3;

    const result = await aiExtractAll(newReports, apiKey, db, aiModel, concurrency);
    allFindings = result.findings;
    parseErrors = result.errors.length;

    console.log(`  Cost: $${result.totalCost.toFixed(3)} (${result.totalInputTokens} in / ${result.totalOutputTokens} out)`);

    if (result.errors.length > 0) {
      console.log(`\n  Errors (${result.errors.length}):`);
      for (const e of result.errors.slice(0, 10)) {
        console.log(`    \u2717 ${e.id}: ${e.error}`);
      }
      if (result.errors.length > 10) console.log(`    ... and ${result.errors.length - 10} more`);
    }
  } else {
    if (!process.env.ANTHROPIC_API_KEY && !process.argv.includes("--regex")) {
      console.log("  (Set ANTHROPIC_API_KEY for AI extraction \u2014 3-4x more findings)\n");
    }
    allFindings = [];
    parseErrors = 0;
    let parsed = 0;

    for (const report of newReports) {
      try {
        const findings = await extractFromPdf(report.path, report.source);
        allFindings.push(...findings);

        // Write regex findings to DB
        const extractionId = db.beginExtraction(report.source.id, "regex", "regex", "regex");
        db.insertFindings(findings.map((f) => ({
          report_id: report.source.id,
          extraction_id: extractionId,
          severity: f.severity,
          title: f.title,
          description: f.description,
          category: f.category,
          cwe: f.cwe,
        })));
        db.completeExtraction(extractionId, findings.length);

        if (findings.length > 0) {
          console.log(`  \u2713 ${report.source.id}: ${findings.length} findings`);
        }
        parsed++;
      } catch (error) {
        console.error(`[sentinel-kb] Failed to extract findings from ${report.source.id}: ${error instanceof Error ? error.message : error}`);
        parseErrors++;
      }
    }
    console.log(`\n  Parsed: ${parsed} PDFs`);
  }

  console.log(`  Extracted: ${allFindings.length} total findings (${parseErrors} errors)\n`);

  // ── Step 4: Save knowledge base ──
  console.log("\u2500\u2500 Step 4: Building knowledge base \u2500\u2500\n");

  // Export JSON for backwards compatibility
  const jsonCount = db.exportToJson(FINDINGS_PATH);
  console.log(`  JSON export: ${jsonCount} findings \u2192 ${FINDINGS_PATH}`);

  // Run dedup pass
  console.log("  Running deduplication...");
  const reportIds = new Set(allFindings.map((f) => f.sourceId));
  for (const reportId of reportIds) {
    db.deduplicateReport(reportId);
  }

  // Summary from DB
  const stats = db.getStats();

  console.log(`\n  Severity: critical=${stats.by_severity.critical || 0} high=${stats.by_severity.high || 0} medium=${stats.by_severity.medium || 0} low=${stats.by_severity.low || 0} info=${stats.by_severity.info || 0}`);

  console.log("\n  By category:");
  for (const [cat, n] of Object.entries(stats.by_category).slice(0, 10)) {
    console.log(`    ${cat}: ${n}`);
  }

  console.log("\n  By firm:");
  for (const [firm, n] of Object.entries(stats.by_firm).slice(0, 15)) {
    console.log(`    ${firm}: ${n}`);
  }

  if (Object.keys(stats.by_model).length > 0) {
    console.log("\n  By model:");
    for (const [model, data] of Object.entries(stats.by_model)) {
      console.log(`    ${model}: ${data.reports} reports, ${data.findings} findings, $${data.cost_usd.toFixed(3)}`);
    }
  }

  console.log(`\n  Canonical patterns: ${stats.canonical_count}`);

  console.log("\n\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
  console.log(`  Knowledge base: ${stats.total_findings} findings from ${stats.total_firms} firms`);
  console.log(`  Database: ${path.join(BASE_DIR, "audit.db")}`);
  console.log(`  PDFs cached: ${validReports.length}`);
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");

  closeDB();
}

main().catch((err) => {
  closeDB();
  console.error("Update failed:", err.message);
  process.exit(1);
});
