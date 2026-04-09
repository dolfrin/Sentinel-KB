// Production knowledge base — SQLite with FTS5, model versioning, dedup, cost tracking

import Database from "better-sqlite3";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import type { ExtractedFinding, ReportInfo } from "./extractor.js";

const DEFAULT_DB_DIR = path.join(process.env.HOME || "~", ".security-audit-kb");
const DEFAULT_DB_PATH = path.join(DEFAULT_DB_DIR, "audit.db");

// ─── Types ────────────────────────────────────────────────────

export interface ReportRow {
  id: string;
  firm: string;
  target: string;
  year: number | null;
  url: string;
  filename: string | null;
  pdf_hash: string | null;
  pdf_size: number | null;
  download_status: string;
  download_error: string | null;
  discovered_at: string;
  downloaded_at: string | null;
}

export interface FindingRow {
  id: number;
  report_id: string;
  extraction_id: number;
  severity: string;
  title: string;
  description: string;
  category: string;
  cwe: string | null;
  confidence: number;
  canonical_id: number | null;
  // joined from reports:
  firm?: string;
  target?: string;
}

export interface FindingInsert {
  report_id: string;
  extraction_id: number;
  severity: string;
  title: string;
  description: string;
  category: string;
  cwe?: string | null;
}

export interface ExtractionRow {
  id: number;
  report_id: string;
  model: string;
  model_slug: string;
  method: string;
  finding_count: number;
  input_tokens: number | null;
  output_tokens: number | null;
  cost_usd: number | null;
  duration_ms: number | null;
  error: string | null;
  started_at: string;
  completed_at: string | null;
}

export interface KBStats {
  total_findings: number;
  total_reports: number;
  total_firms: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_firm: Record<string, number>;
  by_model: Record<string, { reports: number; findings: number; cost_usd: number }>;
  canonical_count: number;
}

// ─── Internal query result shapes ────────────────────────────

interface SchemaVersionRow {
  v: number | null;
}

interface CountRow {
  n: number;
}

interface SeverityCountRow {
  severity: string;
  n: number;
}

interface CategoryCountRow {
  category: string;
  n: number;
}

interface FirmCountRow {
  firm: string;
  n: number;
}

interface ModelStatsRow {
  model_slug: string;
  reports: number;
  findings: number | null;
  cost_usd: number | null;
}

interface CanonicalRow {
  id: number;
  title: string;
  title_normalized: string;
  description: string;
  category: string;
  cwe: string | null;
  severity_mode: string | null;
  occurrence_count: number;
  report_count: number;
  avg_confidence: number;
}

// ─── Database ─────────────────────────────────────────────────

export class SecurityAuditDB {
  private db: Database.Database;

  // Prepared statements (initialized in constructor)
  private stmts!: {
    upsertReport: Database.Statement;
    getReport: Database.Statement;
    getReportsByStatus: Database.Statement;
    updateDownloadStatus: Database.Statement;
    getReportsNeedingExtraction: Database.Statement;

    beginExtraction: Database.Statement;
    completeExtraction: Database.Statement;
    failExtraction: Database.Statement;
    getExtraction: Database.Statement;

    insertFinding: Database.Statement;
    getFindingsForReport: Database.Statement;
    getFindingsForExtraction: Database.Statement;
    getFindingsByCategory: Database.Statement;
    getRelevantFindings: Database.Statement;
    getAllFindings: Database.Statement;
    getAllFindingsWithReport: Database.Statement;

    findCanonical: Database.Statement;
    insertCanonical: Database.Statement;
    updateCanonicalCounts: Database.Statement;
    linkToCanonical: Database.Statement;

    beginModelRun: Database.Statement;
    completeModelRun: Database.Statement;

    countFindings: Database.Statement;
    countReports: Database.Statement;
    countFirms: Database.Statement;
    countCanonical: Database.Statement;
    findingsBySeverity: Database.Statement;
    findingsByCategory: Database.Statement;
    findingsByFirm: Database.Statement;
    extractionsByModel: Database.Statement;
  };

  constructor(dbPath: string = DEFAULT_DB_PATH) {
    const dir = path.dirname(dbPath);
    fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.pragma("synchronous = NORMAL");

    this.ensureSchema();
    this.prepareStatements();
  }

  close() {
    this.db.close();
  }

  // ─── Schema ───────────────────────────────────────────────

  private ensureSchema() {
    this.db.exec(`CREATE TABLE IF NOT EXISTS schema_version (
      version     INTEGER PRIMARY KEY,
      applied_at  TEXT NOT NULL DEFAULT (datetime('now')),
      description TEXT
    )`);

    const row = this.db.prepare("SELECT MAX(version) as v FROM schema_version").get() as SchemaVersionRow | undefined;
    const currentVersion = row?.v ?? 0;

    if (currentVersion < 1) this.migrateV1();
  }

  private migrateV1() {
    this.db.exec(`
      -- ── Reports ──
      CREATE TABLE IF NOT EXISTS reports (
        id              TEXT PRIMARY KEY,
        firm            TEXT NOT NULL,
        target          TEXT NOT NULL,
        year            INTEGER,
        url             TEXT NOT NULL DEFAULT '',
        filename        TEXT,
        pdf_hash        TEXT,
        pdf_size        INTEGER,
        download_status TEXT NOT NULL DEFAULT 'pending',
        download_error  TEXT,
        discovered_at   TEXT NOT NULL DEFAULT (datetime('now')),
        downloaded_at   TEXT,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_reports_firm ON reports(firm);
      CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target);
      CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(download_status);
      CREATE INDEX IF NOT EXISTS idx_reports_pdf_hash ON reports(pdf_hash) WHERE pdf_hash IS NOT NULL;

      -- ── Extractions ──
      CREATE TABLE IF NOT EXISTS extractions (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id     TEXT NOT NULL REFERENCES reports(id),
        model         TEXT NOT NULL,
        model_slug    TEXT NOT NULL,
        method        TEXT NOT NULL DEFAULT 'ai',
        finding_count INTEGER NOT NULL DEFAULT 0,
        input_tokens  INTEGER,
        output_tokens INTEGER,
        cost_usd      REAL,
        duration_ms   INTEGER,
        error         TEXT,
        started_at    TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at  TEXT,
        created_at    TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_extractions_report ON extractions(report_id);
      CREATE INDEX IF NOT EXISTS idx_extractions_model ON extractions(model_slug);
      CREATE INDEX IF NOT EXISTS idx_extractions_report_model ON extractions(report_id, model_slug);

      -- ── Findings ──
      CREATE TABLE IF NOT EXISTS findings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id       TEXT NOT NULL REFERENCES reports(id),
        extraction_id   INTEGER NOT NULL REFERENCES extractions(id),
        severity        TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
        title           TEXT NOT NULL,
        description     TEXT NOT NULL DEFAULT '',
        category        TEXT NOT NULL DEFAULT 'General',
        cwe             TEXT,
        confidence      REAL DEFAULT 1.0,
        canonical_id    INTEGER REFERENCES canonical_findings(id),
        created_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_findings_report ON findings(report_id);
      CREATE INDEX IF NOT EXISTS idx_findings_extraction ON findings(extraction_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
      CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe) WHERE cwe IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_findings_canonical ON findings(canonical_id) WHERE canonical_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_findings_cat_sev ON findings(category, severity);

      -- ── Canonical findings (cross-report dedup) ──
      CREATE TABLE IF NOT EXISTS canonical_findings (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        title             TEXT NOT NULL,
        title_normalized  TEXT NOT NULL UNIQUE,
        description       TEXT NOT NULL DEFAULT '',
        category          TEXT NOT NULL DEFAULT 'General',
        cwe               TEXT,
        severity_mode     TEXT,
        occurrence_count  INTEGER NOT NULL DEFAULT 1,
        report_count      INTEGER NOT NULL DEFAULT 1,
        avg_confidence    REAL DEFAULT 1.0,
        created_at        TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE INDEX IF NOT EXISTS idx_canonical_category ON canonical_findings(category);
      CREATE INDEX IF NOT EXISTS idx_canonical_cwe ON canonical_findings(cwe) WHERE cwe IS NOT NULL;

      -- ── Model runs (cost/performance tracking) ──
      CREATE TABLE IF NOT EXISTS model_runs (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        model             TEXT NOT NULL,
        model_slug        TEXT NOT NULL,
        run_type          TEXT NOT NULL DEFAULT 'extraction',
        reports_processed INTEGER NOT NULL DEFAULT 0,
        findings_total    INTEGER NOT NULL DEFAULT 0,
        input_tokens      INTEGER NOT NULL DEFAULT 0,
        output_tokens     INTEGER NOT NULL DEFAULT 0,
        cost_usd          REAL NOT NULL DEFAULT 0,
        duration_ms       INTEGER NOT NULL DEFAULT 0,
        started_at        TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at      TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_model_runs_model ON model_runs(model_slug);

      -- ── FTS5 for full-text search ──
      CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
        title,
        description,
        category,
        cwe,
        content='findings',
        content_rowid='id',
        tokenize='porter unicode61'
      );

      -- FTS sync triggers
      CREATE TRIGGER IF NOT EXISTS findings_fts_insert AFTER INSERT ON findings BEGIN
        INSERT INTO findings_fts(rowid, title, description, category, cwe)
        VALUES (new.id, new.title, new.description, new.category, COALESCE(new.cwe, ''));
      END;

      CREATE TRIGGER IF NOT EXISTS findings_fts_delete BEFORE DELETE ON findings BEGIN
        INSERT INTO findings_fts(findings_fts, rowid, title, description, category, cwe)
        VALUES ('delete', old.id, old.title, old.description, old.category, COALESCE(old.cwe, ''));
      END;

      CREATE TRIGGER IF NOT EXISTS findings_fts_update AFTER UPDATE ON findings BEGIN
        INSERT INTO findings_fts(findings_fts, rowid, title, description, category, cwe)
        VALUES ('delete', old.id, old.title, old.description, old.category, COALESCE(old.cwe, ''));
        INSERT INTO findings_fts(rowid, title, description, category, cwe)
        VALUES (new.id, new.title, new.description, new.category, COALESCE(new.cwe, ''));
      END;

      -- Record migration
      INSERT INTO schema_version (version, description) VALUES (1, 'Initial schema with FTS5');
    `);
  }

  // ─── Prepared Statements ──────────────────────────────────

  private prepareStatements() {
    this.stmts = {
      // Reports
      upsertReport: this.db.prepare(`
        INSERT INTO reports (id, firm, target, year, url, filename, download_status)
        VALUES (@id, @firm, @target, @year, @url, @filename, @download_status)
        ON CONFLICT(id) DO UPDATE SET
          firm = COALESCE(@firm, firm),
          target = COALESCE(@target, target),
          url = CASE WHEN @url != '' THEN @url ELSE url END,
          updated_at = datetime('now')
      `),
      getReport: this.db.prepare("SELECT * FROM reports WHERE id = ?"),
      getReportsByStatus: this.db.prepare("SELECT * FROM reports WHERE download_status = ?"),
      updateDownloadStatus: this.db.prepare(`
        UPDATE reports SET
          download_status = @status,
          download_error = @error,
          pdf_hash = @pdf_hash,
          pdf_size = @pdf_size,
          downloaded_at = CASE WHEN @status = 'downloaded' THEN datetime('now') ELSE downloaded_at END,
          updated_at = datetime('now')
        WHERE id = @id
      `),
      getReportsNeedingExtraction: this.db.prepare(`
        SELECT r.* FROM reports r
        WHERE r.download_status = 'downloaded'
          AND r.id NOT IN (
            SELECT e.report_id FROM extractions e
            WHERE e.model_slug = ? AND e.error IS NULL
          )
      `),

      // Extractions
      beginExtraction: this.db.prepare(`
        INSERT INTO extractions (report_id, model, model_slug, method)
        VALUES (@report_id, @model, @model_slug, @method)
      `),
      completeExtraction: this.db.prepare(`
        UPDATE extractions SET
          finding_count = @finding_count,
          input_tokens = @input_tokens,
          output_tokens = @output_tokens,
          cost_usd = @cost_usd,
          duration_ms = @duration_ms,
          completed_at = datetime('now')
        WHERE id = @id
      `),
      failExtraction: this.db.prepare(`
        UPDATE extractions SET error = @error, completed_at = datetime('now')
        WHERE id = @id
      `),
      getExtraction: this.db.prepare(`
        SELECT * FROM extractions
        WHERE report_id = ? AND model_slug = ? AND error IS NULL
        ORDER BY created_at DESC LIMIT 1
      `),

      // Findings
      insertFinding: this.db.prepare(`
        INSERT INTO findings (report_id, extraction_id, severity, title, description, category, cwe)
        VALUES (@report_id, @extraction_id, @severity, @title, @description, @category, @cwe)
      `),
      getFindingsForReport: this.db.prepare(`
        SELECT f.*, r.firm, r.target FROM findings f
        JOIN reports r ON f.report_id = r.id
        WHERE f.report_id = ?
      `),
      getFindingsForExtraction: this.db.prepare(`
        SELECT f.*, r.firm, r.target FROM findings f
        JOIN reports r ON f.report_id = r.id
        WHERE f.extraction_id = ?
      `),
      getFindingsByCategory: this.db.prepare(`
        SELECT f.*, r.firm, r.target FROM findings f
        JOIN reports r ON f.report_id = r.id
        WHERE f.category = ?
        ORDER BY CASE f.severity
          WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
          f.confidence DESC
        LIMIT ?
      `),
      getRelevantFindings: this.db.prepare(`
        SELECT f.*, r.firm, r.target FROM findings f
        JOIN reports r ON f.report_id = r.id
        ORDER BY CASE f.severity
          WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
          f.confidence DESC
        LIMIT ?
      `),
      getAllFindings: this.db.prepare("SELECT * FROM findings"),
      getAllFindingsWithReport: this.db.prepare(`
        SELECT f.*, r.firm, r.target FROM findings f
        JOIN reports r ON f.report_id = r.id
      `),

      // Canonical dedup
      findCanonical: this.db.prepare(
        "SELECT * FROM canonical_findings WHERE title_normalized = ?"
      ),
      insertCanonical: this.db.prepare(`
        INSERT INTO canonical_findings (title, title_normalized, description, category, cwe, severity_mode)
        VALUES (@title, @title_normalized, @description, @category, @cwe, @severity_mode)
      `),
      updateCanonicalCounts: this.db.prepare(`
        UPDATE canonical_findings SET
          occurrence_count = (SELECT COUNT(*) FROM findings WHERE canonical_id = @id),
          report_count = (SELECT COUNT(DISTINCT report_id) FROM findings WHERE canonical_id = @id),
          updated_at = datetime('now')
        WHERE id = @id
      `),
      linkToCanonical: this.db.prepare(
        "UPDATE findings SET canonical_id = ? WHERE id = ?"
      ),

      // Model runs
      beginModelRun: this.db.prepare(`
        INSERT INTO model_runs (model, model_slug, run_type)
        VALUES (@model, @model_slug, @run_type)
      `),
      completeModelRun: this.db.prepare(`
        UPDATE model_runs SET
          reports_processed = @reports_processed,
          findings_total = @findings_total,
          input_tokens = @input_tokens,
          output_tokens = @output_tokens,
          cost_usd = @cost_usd,
          duration_ms = @duration_ms,
          completed_at = datetime('now')
        WHERE id = @id
      `),

      // Stats
      countFindings: this.db.prepare("SELECT COUNT(*) as n FROM findings"),
      countReports: this.db.prepare("SELECT COUNT(*) as n FROM reports WHERE download_status = 'downloaded'"),
      countFirms: this.db.prepare("SELECT COUNT(DISTINCT firm) as n FROM reports WHERE download_status = 'downloaded'"),
      countCanonical: this.db.prepare("SELECT COUNT(*) as n FROM canonical_findings"),
      findingsBySeverity: this.db.prepare("SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"),
      findingsByCategory: this.db.prepare("SELECT category, COUNT(*) as n FROM findings GROUP BY category ORDER BY n DESC"),
      findingsByFirm: this.db.prepare(`
        SELECT r.firm, COUNT(*) as n FROM findings f
        JOIN reports r ON f.report_id = r.id
        GROUP BY r.firm ORDER BY n DESC
      `),
      extractionsByModel: this.db.prepare(`
        SELECT model_slug,
          COUNT(*) as reports,
          SUM(finding_count) as findings,
          SUM(COALESCE(cost_usd, 0)) as cost_usd
        FROM extractions WHERE error IS NULL
        GROUP BY model_slug
      `),
    };
  }

  // ─── Reports ──────────────────────────────────────────────

  upsertReport(report: {
    id: string; firm: string; target: string;
    year?: number | null; url?: string; filename?: string | null;
    download_status?: string;
  }) {
    this.stmts.upsertReport.run({
      id: report.id,
      firm: report.firm,
      target: report.target,
      year: report.year ?? null,
      url: report.url ?? "",
      filename: report.filename ?? null,
      download_status: report.download_status ?? "pending",
    });
  }

  getReport(id: string): ReportRow | undefined {
    return this.stmts.getReport.get(id) as ReportRow | undefined;
  }

  getReportsByStatus(status: string): ReportRow[] {
    return this.stmts.getReportsByStatus.all(status) as ReportRow[];
  }

  updateDownloadStatus(
    id: string,
    status: string,
    opts?: { error?: string; pdfPath?: string }
  ) {
    let pdf_hash: string | null = null;
    let pdf_size: number | null = null;

    if (opts?.pdfPath) {
      try {
        const buf = fs.readFileSync(opts.pdfPath);
        pdf_hash = crypto.createHash("sha256").update(buf).digest("hex");
        pdf_size = buf.length;
      } catch {
        // File not available — skip hash computation
      }
    }

    this.stmts.updateDownloadStatus.run({
      id,
      status,
      error: opts?.error ?? null,
      pdf_hash,
      pdf_size,
    });
  }

  getReportsNeedingExtraction(modelSlug: string): ReportRow[] {
    return this.stmts.getReportsNeedingExtraction.all(modelSlug) as ReportRow[];
  }

  // ─── Extractions ──────────────────────────────────────────

  beginExtraction(reportId: string, model: string, modelSlug: string, method: string = "ai"): number {
    // Delete previous failed extraction for this report+model
    this.db.prepare(
      "DELETE FROM extractions WHERE report_id = ? AND model_slug = ? AND error IS NOT NULL"
    ).run(reportId, modelSlug);

    const info = this.stmts.beginExtraction.run({
      report_id: reportId,
      model,
      model_slug: modelSlug,
      method,
    });
    return Number(info.lastInsertRowid);
  }

  completeExtraction(
    id: number,
    findingCount: number,
    opts?: { input_tokens?: number; output_tokens?: number; cost_usd?: number; duration_ms?: number }
  ) {
    this.stmts.completeExtraction.run({
      id,
      finding_count: findingCount,
      input_tokens: opts?.input_tokens ?? null,
      output_tokens: opts?.output_tokens ?? null,
      cost_usd: opts?.cost_usd ?? null,
      duration_ms: opts?.duration_ms ?? null,
    });
  }

  failExtraction(id: number, error: string) {
    this.stmts.failExtraction.run({ id, error });
  }

  getExtraction(reportId: string, modelSlug: string): ExtractionRow | undefined {
    return this.stmts.getExtraction.get(reportId, modelSlug) as ExtractionRow | undefined;
  }

  isExtracted(reportId: string, modelSlug: string): boolean {
    return !!this.getExtraction(reportId, modelSlug);
  }

  // ─── Findings ─────────────────────────────────────────────

  insertFinding(finding: FindingInsert): number {
    const info = this.stmts.insertFinding.run({
      report_id: finding.report_id,
      extraction_id: finding.extraction_id,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      category: finding.category,
      cwe: finding.cwe ?? null,
    });
    return Number(info.lastInsertRowid);
  }

  insertFindings(findings: FindingInsert[]) {
    const insert = this.db.transaction((items: FindingInsert[]) => {
      for (const f of items) this.insertFinding(f);
    });
    insert(findings);
  }

  getFindingsForReport(reportId: string): FindingRow[] {
    return this.stmts.getFindingsForReport.all(reportId) as FindingRow[];
  }

  getFindingsForExtraction(extractionId: number): FindingRow[] {
    return this.stmts.getFindingsForExtraction.all(extractionId) as FindingRow[];
  }

  getFindingsByCategory(category: string, limit: number = 100): FindingRow[] {
    return this.stmts.getFindingsByCategory.all(category, limit) as FindingRow[];
  }

  /** Get findings filtered by multiple categories — for AI scanner */
  getRelevantFindingsByCategories(categories: string[], maxPerCategory: number = 20): FindingRow[] {
    if (categories.length === 0) {
      return this.stmts.getRelevantFindings.all(maxPerCategory * 5) as FindingRow[];
    }

    const placeholders = categories.map(() => "?").join(",");
    const stmt = this.db.prepare(`
      SELECT f.*, r.firm, r.target FROM findings f
      JOIN reports r ON f.report_id = r.id
      WHERE f.category IN (${placeholders})
      ORDER BY CASE f.severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
        f.confidence DESC
      LIMIT ?
    `);
    return stmt.all(...categories, maxPerCategory * categories.length) as FindingRow[];
  }

  /** FTS5 full-text search */
  searchFindings(query: string, limit: number = 50): FindingRow[] {
    const stmt = this.db.prepare(`
      SELECT f.*, r.firm, r.target FROM findings f
      JOIN reports r ON f.report_id = r.id
      WHERE f.id IN (
        SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?
      )
      ORDER BY CASE f.severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
      LIMIT ?
    `);
    try {
      return stmt.all(query, limit) as FindingRow[];
    } catch {
      return []; // invalid FTS query
    }
  }

  /** FTS5 search filtered by categories */
  searchFindingsByCategory(query: string, categories: string[], limit: number = 50): FindingRow[] {
    if (categories.length === 0) return this.searchFindings(query, limit);

    const placeholders = categories.map(() => "?").join(",");
    const stmt = this.db.prepare(`
      SELECT f.*, r.firm, r.target FROM findings f
      JOIN reports r ON f.report_id = r.id
      WHERE f.id IN (
        SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?
      )
      AND f.category IN (${placeholders})
      ORDER BY CASE f.severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
      LIMIT ?
    `);
    try {
      return stmt.all(query, ...categories, limit) as FindingRow[];
    } catch {
      return [];
    }
  }

  getAllFindings(): FindingRow[] {
    return this.stmts.getAllFindingsWithReport.all() as FindingRow[];
  }

  // ─── Canonical Dedup ──────────────────────────────────────

  private normalizeTitle(title: string): string {
    return title
      .toLowerCase()
      .replace(/^[a-z]{2,8}\d{0,4}[-_][a-z0-9]+-?\d*\s*[:\-\u2013\u2014]\s*/i, "") // strip finding IDs
      .replace(/\s+/g, " ")
      .trim();
  }

  findOrCreateCanonical(title: string, category: string, cwe?: string | null, severity?: string): number {
    const normalized = this.normalizeTitle(title);
    const existing = this.stmts.findCanonical.get(normalized) as CanonicalRow | undefined;
    if (existing) return existing.id;

    const info = this.stmts.insertCanonical.run({
      title,
      title_normalized: normalized,
      description: "",
      category,
      cwe: cwe ?? null,
      severity_mode: severity ?? "info",
    });
    return Number(info.lastInsertRowid);
  }

  linkToCanonical(findingId: number, canonicalId: number) {
    this.stmts.linkToCanonical.run(canonicalId, findingId);
  }

  /** Run dedup pass on all findings for a report */
  deduplicateReport(reportId: string) {
    const findings = this.getFindingsForReport(reportId);
    for (const f of findings) {
      const canonId = this.findOrCreateCanonical(f.title, f.category, f.cwe, f.severity);
      this.linkToCanonical(f.id, canonId);
    }
    // Update counts
    const canonIds = new Set(findings.map((f) => this.normalizeTitle(f.title)));
    for (const normalized of canonIds) {
      const c = this.stmts.findCanonical.get(normalized) as CanonicalRow | undefined;
      if (c) this.stmts.updateCanonicalCounts.run({ id: c.id });
    }
  }

  // ─── Model Runs ───────────────────────────────────────────

  beginModelRun(model: string, modelSlug: string, runType: string = "extraction"): number {
    const info = this.stmts.beginModelRun.run({ model, model_slug: modelSlug, run_type: runType });
    return Number(info.lastInsertRowid);
  }

  completeModelRun(id: number, stats: {
    reports_processed: number; findings_total: number;
    input_tokens: number; output_tokens: number;
    cost_usd: number; duration_ms: number;
  }) {
    this.stmts.completeModelRun.run({ id, ...stats });
  }

  // ─── Stats ────────────────────────────────────────────────

  getStats(): KBStats {
    const bySeverity: Record<string, number> = {};
    for (const row of this.stmts.findingsBySeverity.all() as SeverityCountRow[]) {
      bySeverity[row.severity] = row.n;
    }

    const byCategory: Record<string, number> = {};
    for (const row of this.stmts.findingsByCategory.all() as CategoryCountRow[]) {
      byCategory[row.category] = row.n;
    }

    const byFirm: Record<string, number> = {};
    for (const row of this.stmts.findingsByFirm.all() as FirmCountRow[]) {
      byFirm[row.firm] = row.n;
    }

    const byModel: Record<string, { reports: number; findings: number; cost_usd: number }> = {};
    for (const row of this.stmts.extractionsByModel.all() as ModelStatsRow[]) {
      byModel[row.model_slug] = {
        reports: row.reports,
        findings: row.findings ?? 0,
        cost_usd: row.cost_usd ?? 0,
      };
    }

    return {
      total_findings: (this.stmts.countFindings.get() as CountRow).n,
      total_reports: (this.stmts.countReports.get() as CountRow).n,
      total_firms: (this.stmts.countFirms.get() as CountRow).n,
      by_severity: bySeverity,
      by_category: byCategory,
      by_firm: byFirm,
      by_model: byModel,
      canonical_count: (this.stmts.countCanonical.get() as CountRow).n,
    };
  }

  // ─── Migration from JSON ──────────────────────────────────

  importFromJson(jsonPath: string, modelSlug: string = "regex"): { reports: number; findings: number } {
    let raw: ExtractedFinding[];
    try {
      raw = JSON.parse(fs.readFileSync(jsonPath, "utf-8"));
    } catch {
      return { reports: 0, findings: 0 };
    }
    if (!Array.isArray(raw) || raw.length === 0) return { reports: 0, findings: 0 };

    // Group by sourceId
    const bySource = new Map<string, ExtractedFinding[]>();
    for (const f of raw) {
      const key = f.sourceId;
      if (!bySource.has(key)) bySource.set(key, []);
      bySource.get(key)!.push(f);
    }

    let reportCount = 0;
    let findingCount = 0;

    const importAll = this.db.transaction(() => {
      for (const [sourceId, findings] of bySource) {
        const first = findings[0];

        // Upsert report
        this.upsertReport({
          id: sourceId,
          firm: first.firm,
          target: first.target,
          download_status: "downloaded",
        });
        reportCount++;

        // Create extraction record
        const extractionId = this.beginExtraction(sourceId, modelSlug, modelSlug, modelSlug === "regex" ? "regex" : "ai");

        // Insert findings
        for (const f of findings) {
          this.insertFinding({
            report_id: sourceId,
            extraction_id: extractionId,
            severity: f.severity,
            title: f.title,
            description: f.description,
            category: f.category,
            cwe: f.cwe,
          });
          findingCount++;
        }

        this.completeExtraction(extractionId, findings.length);
      }
    });

    importAll();
    return { reports: reportCount, findings: findingCount };
  }

  /** Import from per-model cache directories (extracted/sonnet/*.json, etc.) */
  importFromCache(cacheDir: string): { models: string[]; reports: number; findings: number } {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(cacheDir, { withFileTypes: true });
    } catch {
      return { models: [], reports: 0, findings: 0 };
    }

    const models: string[] = [];
    let totalReports = 0;
    let totalFindings = 0;


    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const slug = entry.name;
      models.push(slug);

      const modelDir = path.join(cacheDir, slug);
      const files = fs.readdirSync(modelDir).filter((f) => f.endsWith(".json"));

      const importModel = this.db.transaction(() => {
        for (const file of files) {
          const sourceId = file.replace(/\.json$/, "");
          const findings: ExtractedFinding[] = JSON.parse(
            fs.readFileSync(path.join(modelDir, file), "utf-8")
          );

          if (!this.getReport(sourceId)) {
            const first = findings[0];
            this.upsertReport({
              id: sourceId,
              firm: first?.firm ?? "Unknown",
              target: first?.target ?? sourceId,
              download_status: "downloaded",
            });
          }

          if (this.isExtracted(sourceId, slug)) continue;

          const extractionId = this.beginExtraction(sourceId, `claude-${slug}`, slug, "ai");

          for (const f of findings) {
            this.insertFinding({
              report_id: sourceId,
              extraction_id: extractionId,
              severity: f.severity,
              title: f.title,
              description: f.description,
              category: f.category,
              cwe: f.cwe,
            });
            totalFindings++;
          }

          this.completeExtraction(extractionId, findings.length);
          totalReports++;
        }
      });

      importModel();
    }

    return { models, reports: totalReports, findings: totalFindings };
  }

  /** Export to flat JSON for backwards compatibility */
  exportToJson(outputPath: string): number {
    const rows = this.getAllFindings();
    const findings = rows.map((r) => this.toExtractedFinding(r));
    const dir = path.dirname(outputPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(findings, null, 2));
    return findings.length;
  }

  // ─── Compat ───────────────────────────────────────────────

  toExtractedFinding(row: FindingRow): ExtractedFinding {
    return {
      sourceId: row.report_id,
      firm: row.firm ?? "Unknown",
      target: row.target ?? row.report_id,
      severity: row.severity as ExtractedFinding["severity"],
      title: row.title,
      description: row.description,
      category: row.category,
      cwe: row.cwe ?? undefined,
    };
  }

  toExtractedFindings(rows: FindingRow[]): ExtractedFinding[] {
    return rows.map((r) => this.toExtractedFinding(r));
  }
}

// ─── Singleton ──────────────────────────────────────────────

let instance: SecurityAuditDB | null = null;

export function getDB(dbPath?: string): SecurityAuditDB {
  if (!instance) instance = new SecurityAuditDB(dbPath);
  return instance;
}

export function closeDB() {
  if (instance) {
    instance.close();
    instance = null;
  }
}

/** Helper: extract model slug from full model ID */
export function modelSlug(model: string): string {
  if (model.includes("opus")) return "opus";
  if (model.includes("sonnet")) return "sonnet";
  if (model.includes("haiku")) return "haiku";
  if (model === "regex") return "regex";
  return model.replace(/[^a-z0-9]/gi, "-");
}
