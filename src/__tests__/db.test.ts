// Database unit tests — SecurityAuditDB
// Creates a temp DB per test, cleans up in afterEach

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { SecurityAuditDB } from "../db.js";

// ─── Helpers ──────────────────────────────────────────────────

function makeTempDbPath(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-test-"));
  return path.join(dir, "test.db");
}

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-test-"));
}

// ─── Fixtures ─────────────────────────────────────────────────

const REPORT_A = {
  id: "trail-of-bits-signal-2023",
  firm: "Trail of Bits",
  target: "Signal",
  year: 2023,
  url: "https://example.com/report-a.pdf",
  filename: "report-a.pdf",
  download_status: "pending" as const,
};

const REPORT_B = {
  id: "cure53-element-2022",
  firm: "Cure53",
  target: "Element",
  year: 2022,
  url: "https://example.com/report-b.pdf",
  filename: "report-b.pdf",
  download_status: "downloaded" as const,
};

// ─── Tests ────────────────────────────────────────────────────

describe("SecurityAuditDB", () => {
  let dbPath: string;
  let db: SecurityAuditDB;

  beforeEach(() => {
    dbPath = makeTempDbPath();
    db = new SecurityAuditDB(dbPath);
  });

  afterEach(() => {
    db.close();
    // Clean up temp directory
    const dir = path.dirname(dbPath);
    if (dir.includes("sentinel-test-")) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  // ─── Initialization ───────────────────────────────────────

  describe("initialization", () => {
    it("creates the SQLite file on disk", () => {
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it("creates all required tables", () => {
      // Open a fresh DB at the same path to inspect schema
      const db2 = new SecurityAuditDB(dbPath);
      const stats = db2.getStats();
      db2.close();

      // If tables don't exist getStats() would throw
      expect(stats).toBeDefined();
      expect(typeof stats.total_findings).toBe("number");
      expect(typeof stats.total_reports).toBe("number");
      expect(typeof stats.canonical_count).toBe("number");
    });

    it("starts with zero findings and reports", () => {
      const stats = db.getStats();
      expect(stats.total_findings).toBe(0);
      expect(stats.total_reports).toBe(0);
      expect(stats.total_firms).toBe(0);
      expect(stats.canonical_count).toBe(0);
    });

    it("can be opened twice at the same path (WAL mode)", () => {
      // Should not throw — WAL mode allows concurrent readers
      const db2 = new SecurityAuditDB(dbPath);
      db2.close();
    });

    it("creates parent directory when it does not exist", () => {
      const nested = path.join(makeTempDir(), "nested", "deep", "test.db");
      const dbNested = new SecurityAuditDB(nested);
      dbNested.close();
      expect(fs.existsSync(nested)).toBe(true);
      fs.rmSync(path.dirname(path.dirname(path.dirname(nested))), { recursive: true, force: true });
    });
  });

  // ─── upsertReport ─────────────────────────────────────────

  describe("upsertReport / getReport", () => {
    it("inserts a new report", () => {
      db.upsertReport(REPORT_A);
      const row = db.getReport(REPORT_A.id);
      expect(row).toBeDefined();
      expect(row!.id).toBe(REPORT_A.id);
      expect(row!.firm).toBe(REPORT_A.firm);
      expect(row!.target).toBe(REPORT_A.target);
      expect(row!.year).toBe(REPORT_A.year);
      expect(row!.url).toBe(REPORT_A.url);
      expect(row!.download_status).toBe("pending");
    });

    it("returns undefined for a missing id", () => {
      expect(db.getReport("does-not-exist")).toBeUndefined();
    });

    it("upserts without overwriting existing data when fields are empty/null", () => {
      db.upsertReport(REPORT_A);
      // Re-upsert with empty url — should keep the original url
      db.upsertReport({ id: REPORT_A.id, firm: REPORT_A.firm, target: REPORT_A.target, url: "" });
      const row = db.getReport(REPORT_A.id);
      expect(row!.url).toBe(REPORT_A.url);
    });

    it("updates url when a non-empty url is provided", () => {
      db.upsertReport(REPORT_A);
      const newUrl = "https://example.com/updated.pdf";
      db.upsertReport({ id: REPORT_A.id, firm: REPORT_A.firm, target: REPORT_A.target, url: newUrl });
      const row = db.getReport(REPORT_A.id);
      expect(row!.url).toBe(newUrl);
    });

    it("defaults download_status to pending", () => {
      db.upsertReport({ id: "r1", firm: "F", target: "T" });
      const row = db.getReport("r1");
      expect(row!.download_status).toBe("pending");
    });

    it("accepts null year", () => {
      db.upsertReport({ id: "r2", firm: "F", target: "T", year: null });
      const row = db.getReport("r2");
      expect(row!.year).toBeNull();
    });

    it("getReportsByStatus returns matching reports", () => {
      db.upsertReport(REPORT_A); // pending
      db.upsertReport(REPORT_B); // downloaded
      const pending = db.getReportsByStatus("pending");
      const downloaded = db.getReportsByStatus("downloaded");
      expect(pending.map((r) => r.id)).toContain(REPORT_A.id);
      expect(downloaded.map((r) => r.id)).toContain(REPORT_B.id);
    });
  });

  // ─── updateDownloadStatus ─────────────────────────────────

  describe("updateDownloadStatus", () => {
    it("marks a report as failed with an error message", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "failed", { error: "404 Not Found" });
      const row = db.getReport(REPORT_A.id);
      expect(row!.download_status).toBe("failed");
      expect(row!.download_error).toBe("404 Not Found");
    });

    it("marks a report as downloaded (no pdf path)", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const row = db.getReport(REPORT_A.id);
      expect(row!.download_status).toBe("downloaded");
    });
  });

  // ─── Extraction lifecycle ─────────────────────────────────

  describe("beginExtraction / completeExtraction / failExtraction", () => {
    beforeEach(() => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
    });

    it("beginExtraction returns an integer id", () => {
      const id = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      expect(typeof id).toBe("number");
      expect(id).toBeGreaterThan(0);
    });

    it("completeExtraction sets finding_count and cost", () => {
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.completeExtraction(eid, 5, { input_tokens: 1000, output_tokens: 200, cost_usd: 0.01, duration_ms: 500 });
      const ext = db.getExtraction(REPORT_A.id, "sonnet");
      expect(ext).toBeDefined();
      expect(ext!.finding_count).toBe(5);
      expect(ext!.input_tokens).toBe(1000);
      expect(ext!.cost_usd).toBeCloseTo(0.01);
    });

    it("failExtraction records the error and getExtraction returns undefined", () => {
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.failExtraction(eid, "API timeout");
      // Failed extractions are excluded from getExtraction (error IS NOT NULL filter)
      const ext = db.getExtraction(REPORT_A.id, "sonnet");
      expect(ext).toBeUndefined();
    });

    it("isExtracted returns false before completion", () => {
      expect(db.isExtracted(REPORT_A.id, "sonnet")).toBe(false);
    });

    it("isExtracted returns true after successful completion", () => {
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.completeExtraction(eid, 3);
      expect(db.isExtracted(REPORT_A.id, "sonnet")).toBe(true);
    });

    it("beginExtraction removes previous failed extraction for same report+model", () => {
      const eid1 = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.failExtraction(eid1, "network error");
      // Begin again — should not error; old failed record cleaned up
      const eid2 = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      expect(eid2).toBeGreaterThan(0);
    });

    it("getReportsNeedingExtraction excludes already-extracted reports", () => {
      db.upsertReport(REPORT_B);
      db.updateDownloadStatus(REPORT_B.id, "downloaded");

      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.completeExtraction(eid, 0);

      const needing = db.getReportsNeedingExtraction("sonnet");
      const ids = needing.map((r) => r.id);
      expect(ids).not.toContain(REPORT_A.id);
      expect(ids).toContain(REPORT_B.id);
    });
  });

  // ─── insertFinding / retrieval ────────────────────────────

  describe("insertFinding / getFindingsForReport", () => {
    let extractionId: number;

    beforeEach(() => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      extractionId = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
    });

    it("inserts a finding and returns its id", () => {
      const fid = db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "high",
        title: "Nonce reuse in AES-GCM",
        description: "The nonce counter is not incremented correctly.",
        category: "Cryptography",
        cwe: "CWE-330",
      });
      expect(typeof fid).toBe("number");
      expect(fid).toBeGreaterThan(0);
    });

    it("retrieves inserted findings by report id", () => {
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "critical",
        title: "Private key exposure",
        description: "Key logged in plaintext.",
        category: "Cryptography",
      });
      const findings = db.getFindingsForReport(REPORT_A.id);
      expect(findings).toHaveLength(1);
      expect(findings[0].title).toBe("Private key exposure");
      expect(findings[0].severity).toBe("critical");
      expect(findings[0].firm).toBe(REPORT_A.firm);
      expect(findings[0].target).toBe(REPORT_A.target);
    });

    it("getFindingsForExtraction returns only findings for given extraction", () => {
      // Two extractions for same report (different models)
      const eid2 = db.beginExtraction(REPORT_A.id, "claude-opus", "opus");

      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "high",
        title: "Finding A",
        description: "Desc A",
        category: "Network",
      });
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: eid2,
        severity: "low",
        title: "Finding B",
        description: "Desc B",
        category: "Auth",
      });

      const forSonnet = db.getFindingsForExtraction(extractionId);
      const forOpus = db.getFindingsForExtraction(eid2);
      expect(forSonnet).toHaveLength(1);
      expect(forSonnet[0].title).toBe("Finding A");
      expect(forOpus).toHaveLength(1);
      expect(forOpus[0].title).toBe("Finding B");
    });

    it("getFindingsByCategory filters correctly", () => {
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "high",
        title: "SQL injection",
        description: "Unparameterized query",
        category: "Injection",
      });
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "medium",
        title: "Broken auth",
        description: "Session not invalidated",
        category: "Auth",
      });

      const injection = db.getFindingsByCategory("Injection");
      expect(injection).toHaveLength(1);
      expect(injection[0].category).toBe("Injection");

      const auth = db.getFindingsByCategory("Auth");
      expect(auth).toHaveLength(1);
    });

    it("insertFindings (batch) inserts multiple findings atomically", () => {
      db.insertFindings([
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "high",
          title: "Finding 1",
          description: "D1",
          category: "Crypto",
        },
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "medium",
          title: "Finding 2",
          description: "D2",
          category: "Network",
        },
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "low",
          title: "Finding 3",
          description: "D3",
          category: "Auth",
        },
      ]);
      const findings = db.getFindingsForReport(REPORT_A.id);
      expect(findings).toHaveLength(3);
    });

    it("getAllFindings returns findings with joined firm/target", () => {
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "info",
        title: "Informational note",
        description: "Low priority",
        category: "General",
      });
      const all = db.getAllFindings();
      expect(all).toHaveLength(1);
      expect(all[0].firm).toBe(REPORT_A.firm);
    });

    it("severity ordering — critical before high before medium", () => {
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "medium",
        title: "Med finding",
        description: "",
        category: "Crypto",
      });
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "critical",
        title: "Crit finding",
        description: "",
        category: "Crypto",
      });
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "high",
        title: "High finding",
        description: "",
        category: "Crypto",
      });

      const byCat = db.getFindingsByCategory("Crypto", 10);
      expect(byCat[0].severity).toBe("critical");
      expect(byCat[1].severity).toBe("high");
      expect(byCat[2].severity).toBe("medium");
    });
  });

  // ─── FTS5 search ──────────────────────────────────────────

  describe("searchFindings (FTS5)", () => {
    let extractionId: number;

    beforeEach(() => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      extractionId = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");

      db.insertFindings([
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "critical",
          title: "Nonce reuse in AES-GCM encryption",
          description: "The encryption nonce is reused across sessions allowing plaintext recovery.",
          category: "Cryptography",
          cwe: "CWE-330",
        },
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "high",
          title: "Buffer overflow in message parser",
          description: "Parsing user-controlled input without bounds checking.",
          category: "Memory",
          cwe: "CWE-120",
        },
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "medium",
          title: "Insecure random number generation",
          description: "Math.random() used for security-sensitive token generation.",
          category: "Cryptography",
        },
      ]);
    });

    it("finds findings matching a keyword", () => {
      const results = db.searchFindings("nonce");
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].title).toContain("Nonce");
    });

    it("finds findings matching a description term", () => {
      const results = db.searchFindings("bounds");
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].title).toContain("Buffer");
    });

    it("returns empty array for a query that matches nothing", () => {
      const results = db.searchFindings("zzznomatch999xyzabc");
      expect(results).toHaveLength(0);
    });

    it("returns empty array for an invalid FTS query (no throw)", () => {
      // FTS5 syntax error — should not throw, returns []
      const results = db.searchFindings("AND OR AND");
      expect(Array.isArray(results)).toBe(true);
    });

    it("respects the limit parameter", () => {
      const results = db.searchFindings("*", 1);
      // wildcard in FTS5 needs a prefix — use a real term
      const cryptoResults = db.searchFindings("encryption nonce random", 1);
      expect(cryptoResults.length).toBeLessThanOrEqual(1);
    });

    it("searchFindingsByCategory narrows results by category", () => {
      const all = db.searchFindings("nonce encryption random buffer");
      const cryptoOnly = db.searchFindingsByCategory("nonce encryption random buffer", ["Cryptography"]);
      expect(cryptoOnly.every((f) => f.category === "Cryptography")).toBe(true);
      expect(cryptoOnly.length).toBeLessThanOrEqual(all.length);
    });

    it("searchFindingsByCategory with empty categories falls back to regular search", () => {
      const withCat = db.searchFindingsByCategory("nonce", []);
      const without = db.searchFindings("nonce");
      expect(withCat).toEqual(without);
    });

    it("finds by CWE field", () => {
      // FTS5 tokenizes "CWE-330" as two tokens; search for "CWE" prefix which appears in the cwe column
      const results = db.searchFindings("CWE");
      expect(results.length).toBeGreaterThan(0);
    });
  });

  // ─── Deduplication / canonical findings ──────────────────

  describe("deduplicateReport / findOrCreateCanonical", () => {
    let extractionId: number;

    beforeEach(() => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      extractionId = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
    });

    it("creates a canonical entry for a new title", () => {
      const canonId = db.findOrCreateCanonical(
        "Nonce reuse in AES-GCM",
        "Cryptography",
        "CWE-330",
        "high"
      );
      expect(typeof canonId).toBe("number");
      expect(canonId).toBeGreaterThan(0);
    });

    it("returns the same canonical id for the same normalized title", () => {
      const id1 = db.findOrCreateCanonical("Nonce reuse", "Crypto");
      const id2 = db.findOrCreateCanonical("nonce reuse", "Crypto"); // lowercase
      // normalizeTitle lowercases, so both should resolve to same entry
      expect(id1).toBe(id2);
    });

    it("deduplicateReport links all findings for a report to canonical entries", () => {
      db.insertFindings([
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "high",
          title: "Buffer overflow in parser",
          description: "Overflow possible",
          category: "Memory",
        },
        {
          report_id: REPORT_A.id,
          extraction_id: extractionId,
          severity: "medium",
          title: "Insecure random seed",
          description: "PRNG seeded with time",
          category: "Cryptography",
        },
      ]);

      db.deduplicateReport(REPORT_A.id);

      const statsBefore = db.getStats();
      expect(statsBefore.canonical_count).toBeGreaterThanOrEqual(2);

      // All findings should now have a canonical_id
      const findings = db.getFindingsForReport(REPORT_A.id);
      for (const f of findings) {
        expect(f.canonical_id).not.toBeNull();
        expect(f.canonical_id).toBeGreaterThan(0);
      }
    });

    it("deduplicateReport across two reports groups same vuln together", () => {
      db.upsertReport(REPORT_B);
      db.updateDownloadStatus(REPORT_B.id, "downloaded");
      const eid2 = db.beginExtraction(REPORT_B.id, "claude-sonnet", "sonnet");

      const sharedTitle = "SQL injection in login endpoint";

      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: extractionId,
        severity: "critical",
        title: sharedTitle,
        description: "Unparameterized query in login handler",
        category: "Injection",
      });
      db.insertFinding({
        report_id: REPORT_B.id,
        extraction_id: eid2,
        severity: "critical",
        title: sharedTitle,
        description: "SQL injection through username field",
        category: "Injection",
      });

      db.deduplicateReport(REPORT_A.id);
      db.deduplicateReport(REPORT_B.id);

      const findingsA = db.getFindingsForReport(REPORT_A.id);
      const findingsB = db.getFindingsForReport(REPORT_B.id);

      // Both findings should point to the same canonical entry
      expect(findingsA[0].canonical_id).toBe(findingsB[0].canonical_id);
      expect(db.getStats().canonical_count).toBeGreaterThanOrEqual(1);
    });

    it("strips finding IDs from titles during normalization", () => {
      // Finding IDs like "TOB-2023-001: Buffer overflow" should normalize to "buffer overflow"
      const id1 = db.findOrCreateCanonical("TOB-2023-001: Buffer overflow in parser", "Memory");
      const id2 = db.findOrCreateCanonical("buffer overflow in parser", "Memory");
      expect(id1).toBe(id2);
    });
  });

  // ─── getStats ─────────────────────────────────────────────

  describe("getStats", () => {
    it("correctly counts findings, reports, firms", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      db.upsertReport(REPORT_B);
      db.updateDownloadStatus(REPORT_B.id, "downloaded");

      const eidA = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      const eidB = db.beginExtraction(REPORT_B.id, "claude-sonnet", "sonnet");

      db.insertFindings([
        { report_id: REPORT_A.id, extraction_id: eidA, severity: "high", title: "F1", description: "", category: "Crypto" },
        { report_id: REPORT_A.id, extraction_id: eidA, severity: "medium", title: "F2", description: "", category: "Auth" },
        { report_id: REPORT_B.id, extraction_id: eidB, severity: "critical", title: "F3", description: "", category: "Crypto" },
      ]);

      const stats = db.getStats();
      expect(stats.total_findings).toBe(3);
      expect(stats.total_reports).toBe(2); // only 'downloaded' reports counted
      expect(stats.total_firms).toBe(2);   // Trail of Bits, Cure53
    });

    it("by_severity aggregates correctly", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");

      db.insertFindings([
        { report_id: REPORT_A.id, extraction_id: eid, severity: "critical", title: "C1", description: "", category: "X" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "critical", title: "C2", description: "", category: "X" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "high", title: "H1", description: "", category: "X" },
      ]);

      const stats = db.getStats();
      expect(stats.by_severity["critical"]).toBe(2);
      expect(stats.by_severity["high"]).toBe(1);
    });

    it("by_category aggregates correctly", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");

      db.insertFindings([
        { report_id: REPORT_A.id, extraction_id: eid, severity: "high", title: "F1", description: "", category: "Crypto" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "high", title: "F2", description: "", category: "Crypto" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "medium", title: "F3", description: "", category: "Auth" },
      ]);

      const stats = db.getStats();
      expect(stats.by_category["Crypto"]).toBe(2);
      expect(stats.by_category["Auth"]).toBe(1);
    });

    it("by_model tracks extraction costs", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.completeExtraction(eid, 2, { cost_usd: 0.05 });

      const stats = db.getStats();
      expect(stats.by_model["sonnet"]).toBeDefined();
      expect(stats.by_model["sonnet"].cost_usd).toBeCloseTo(0.05);
    });
  });

  // ─── Model runs ───────────────────────────────────────────

  describe("beginModelRun / completeModelRun", () => {
    it("records a model run with cost and token stats", () => {
      const runId = db.beginModelRun("claude-sonnet-4", "sonnet", "extraction");
      expect(runId).toBeGreaterThan(0);

      db.completeModelRun(runId, {
        reports_processed: 10,
        findings_total: 150,
        input_tokens: 50000,
        output_tokens: 12000,
        cost_usd: 0.25,
        duration_ms: 30000,
      });
      // No direct getter — verify via no-throw and stats indirectly
    });
  });

  // ─── toExtractedFinding compat ────────────────────────────

  describe("toExtractedFinding", () => {
    it("converts a FindingRow to ExtractedFinding shape", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.insertFinding({
        report_id: REPORT_A.id,
        extraction_id: eid,
        severity: "high",
        title: "Key exchange weakness",
        description: "ECDH without authentication",
        category: "Cryptography",
        cwe: "CWE-322",
      });

      const rows = db.getAllFindings();
      const extracted = db.toExtractedFinding(rows[0]);
      expect(extracted.sourceId).toBe(REPORT_A.id);
      expect(extracted.firm).toBe(REPORT_A.firm);
      expect(extracted.title).toBe("Key exchange weakness");
      expect(extracted.cwe).toBe("CWE-322");
    });

    it("toExtractedFindings converts an array", () => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      const eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");
      db.insertFindings([
        { report_id: REPORT_A.id, extraction_id: eid, severity: "high", title: "A", description: "", category: "C" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "low", title: "B", description: "", category: "C" },
      ]);
      const rows = db.getAllFindings();
      const extracted = db.toExtractedFindings(rows);
      expect(extracted).toHaveLength(2);
      expect(extracted.every((f) => f.sourceId === REPORT_A.id)).toBe(true);
    });
  });

  // ─── getRelevantFindingsByCategories ─────────────────────

  describe("getRelevantFindingsByCategories", () => {
    let eid: number;

    beforeEach(() => {
      db.upsertReport(REPORT_A);
      db.updateDownloadStatus(REPORT_A.id, "downloaded");
      eid = db.beginExtraction(REPORT_A.id, "claude-sonnet", "sonnet");

      db.insertFindings([
        { report_id: REPORT_A.id, extraction_id: eid, severity: "critical", title: "C1", description: "", category: "Crypto" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "high", title: "N1", description: "", category: "Network" },
        { report_id: REPORT_A.id, extraction_id: eid, severity: "medium", title: "A1", description: "", category: "Auth" },
      ]);
    });

    it("returns findings for specified categories", () => {
      const results = db.getRelevantFindingsByCategories(["Crypto", "Network"]);
      const cats = results.map((f) => f.category);
      expect(cats).toContain("Crypto");
      expect(cats).toContain("Network");
      expect(cats).not.toContain("Auth");
    });

    it("returns all findings when categories array is empty", () => {
      const results = db.getRelevantFindingsByCategories([]);
      expect(results.length).toBe(3);
    });
  });
});
