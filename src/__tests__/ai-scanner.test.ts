// Unit tests for src/ai-scanner.ts — error paths and edge cases
// Mocks the Anthropic SDK and DB to avoid real API calls.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// ─── Mocks ──────────────────────────────────────────────────────────────────

// Mock Anthropic SDK — must be declared before import
const mockCreate = vi.fn();
vi.mock("@anthropic-ai/sdk", () => {
  return {
    default: class MockAnthropic {
      messages = { create: mockCreate };
      constructor(_opts?: any) {}
    },
  };
});

// Mock DB — provides getStats, getRelevantFindingsByCategories, toExtractedFindings
const mockGetStats = vi.fn().mockReturnValue({
  total_findings: 100,
  total_reports: 20,
  total_firms: 5,
  by_severity: {},
  by_category: {},
  by_firm: {},
  by_model: {},
  canonical_count: 0,
});
const mockGetRelevantFindingsByCategories = vi.fn().mockReturnValue([]);
const mockToExtractedFindings = vi.fn().mockReturnValue([]);

vi.mock("../db.js", () => ({
  getDB: vi.fn(() => ({
    getStats: mockGetStats,
    getRelevantFindingsByCategories: mockGetRelevantFindingsByCategories,
    toExtractedFindings: mockToExtractedFindings,
  })),
}));

import { aiScan, type AIScanReport, type AIScanFinding } from "../ai-scanner.js";

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-ai-scanner-test-"));
}

function writeFile(dir: string, relPath: string, content: string): string {
  const fullPath = path.join(dir, relPath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, "utf-8");
  return fullPath;
}

/** Build a mock Anthropic messages.create response containing the given text. */
function mockTextResponse(text: string) {
  return {
    content: [{ type: "text", text }],
  };
}

/** Build a valid finding JSON that passes the Zod schema. */
function validFindingJSON(overrides: Partial<AIScanFinding> = {}): AIScanFinding {
  return {
    severity: "high",
    title: "Hardcoded secret key",
    description: "Secret key is hardcoded in source code.",
    file: "src/crypto.ts",
    line: 10,
    category: "Key Management",
    recommendation: "Use environment variables or a secrets manager.",
    confidence: "high",
    ...overrides,
  };
}

// ─── Test state ─────────────────────────────────────────────────────────────

let tmpDir: string;

beforeEach(() => {
  tmpDir = makeTempDir();
  vi.clearAllMocks();
  // Re-apply default mock return values after clearAllMocks
  mockGetStats.mockReturnValue({
    total_findings: 100,
    total_reports: 20,
    total_firms: 5,
    by_severity: {},
    by_category: {},
    by_firm: {},
    by_model: {},
    canonical_count: 0,
  });
  mockGetRelevantFindingsByCategories.mockReturnValue([]);
  mockToExtractedFindings.mockReturnValue([]);
});

afterEach(() => {
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ─── a) Batch API failure ───────────────────────────────────────────────────

describe("aiScan() — batch API failure", () => {
  it("populates errors[] when a batch throws and still returns findings from other batches", async () => {
    // Two source files — should create at least one batch each if we set
    // a very small batch size. Instead we rely on default batching which
    // puts small files together. Create two files large enough to land in
    // separate batches (>30 KB each to exceed maxCharsPerBatch=30000).
    const bigContent = "// " + "x".repeat(31000) + "\n";
    writeFile(tmpDir, "src/a.ts", bigContent);
    writeFile(tmpDir, "src/b.ts", bigContent);

    const goodFinding = validFindingJSON({ file: "src/a.ts" });

    // First call succeeds, second throws
    mockCreate
      .mockResolvedValueOnce(mockTextResponse(JSON.stringify([goodFinding])))
      .mockRejectedValueOnce(new Error("rate limit exceeded"));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.errors.length).toBeGreaterThanOrEqual(1);
    expect(report.errors.some((e) => e.includes("rate limit exceeded"))).toBe(true);
    // Findings from the successful batch are still present
    expect(report.findings.length).toBeGreaterThanOrEqual(1);
    expect(report.findings[0].title).toBe("Hardcoded secret key");
  });

  it("returns empty findings and populated errors when all batches fail", async () => {
    writeFile(tmpDir, "src/app.ts", 'const x = "hello";\n');

    mockCreate.mockRejectedValue(new Error("service unavailable"));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.findings.length).toBe(0);
    expect(report.errors.length).toBeGreaterThanOrEqual(1);
    expect(report.errors[0]).toContain("service unavailable");
  });
});

// ─── b) Bad JSON response ───────────────────────────────────────────────────

describe("aiScan() — bad JSON response", () => {
  it("records a warning when the API returns non-JSON prose", async () => {
    writeFile(tmpDir, "src/app.ts", 'const x = "hello";\n');

    mockCreate.mockResolvedValue(
      mockTextResponse("I could not find any vulnerabilities in the code above.")
    );

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    // No findings since the response was not valid JSON
    expect(report.findings.length).toBe(0);
    // Should report a warning — prose reply means incomplete scan, not a clean bill of health
    expect(report.errors.length).toBeGreaterThanOrEqual(1);
    expect(report.errors.some((e) => e.includes("non-JSON response"))).toBe(true);
  });

  it("records an error when the API returns malformed JSON that matches the array regex", async () => {
    writeFile(tmpDir, "src/app.ts", 'const x = "hello";\n');

    // JSON that has both [ and ] so the regex matches, but is not valid JSON.
    // The regex /\[[\s\S]*\]/ will extract '[{"severity": INVALID}]' which
    // fails JSON.parse and propagates to the batch error handler.
    mockCreate.mockResolvedValue(
      mockTextResponse('[{"severity": INVALID}]')
    );

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    // The malformed JSON will throw a SyntaxError in JSON.parse which
    // propagates up to the batch try/catch and lands in errors[]
    expect(report.errors.length).toBeGreaterThanOrEqual(1);
    expect(report.errors[0]).toMatch(/Batch \d+/);
    expect(report.findings.length).toBe(0);
  });
});

// ─── c) Invalid finding schema ──────────────────────────────────────────────

describe("aiScan() — invalid finding schema", () => {
  it("drops findings with invalid severity while keeping valid ones", async () => {
    writeFile(tmpDir, "src/app.ts", 'const x = "hello";\n');

    const validFinding = validFindingJSON();
    const invalidFinding = {
      ...validFindingJSON({ title: "Bad severity finding" }),
      severity: "super-critical", // not a valid severity
    };

    mockCreate.mockResolvedValue(
      mockTextResponse(JSON.stringify([validFinding, invalidFinding]))
    );

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    // Zod validation drops findings with invalid severity values.
    // The valid finding passes through; the invalid one is dropped.
    const titles = report.findings.map((f) => f.title);
    expect(titles).toContain("Hardcoded secret key");
    expect(titles).not.toContain("Bad severity finding");
    // A warning about the dropped finding should appear in errors
    expect(report.errors.length).toBeGreaterThanOrEqual(1);
    expect(report.errors[0]).toMatch(/1\/2 findings dropped \(invalid schema\)/);
  });

  it("drops low-confidence findings", async () => {
    writeFile(tmpDir, "src/app.ts", 'const x = "hello";\n');

    const highConf = validFindingJSON({ title: "Real issue", confidence: "high" });
    const lowConf = validFindingJSON({ title: "Maybe issue", confidence: "low" });
    const medConf = validFindingJSON({ title: "Likely issue", confidence: "medium" });

    mockCreate.mockResolvedValue(
      mockTextResponse(JSON.stringify([highConf, lowConf, medConf]))
    );

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    const titles = report.findings.map((f) => f.title);
    expect(titles).toContain("Real issue");
    expect(titles).toContain("Likely issue");
    expect(titles).not.toContain("Maybe issue");
  });
});

// ─── d) Empty source files ──────────────────────────────────────────────────

describe("aiScan() — empty source files", () => {
  it("returns clean report with 0 findings when directory has no source files", async () => {
    // tmpDir is empty — no source files to scan
    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.findings.length).toBe(0);
    expect(report.errors.length).toBe(0);
    expect(report.filesScanned).toBe(0);
    // Anthropic API should not have been called at all
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it("returns clean report when directory has only non-source files", async () => {
    writeFile(tmpDir, "README.md", "# Hello");
    writeFile(tmpDir, "photo.png", "fake-png-data");
    writeFile(tmpDir, ".gitignore", "node_modules/");

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.findings.length).toBe(0);
    expect(report.errors.length).toBe(0);
    expect(report.filesScanned).toBe(0);
    expect(mockCreate).not.toHaveBeenCalled();
  });
});

// ─── e) Report errors field ─────────────────────────────────────────────────

describe("aiScan() — report errors field", () => {
  it("clean scan has errors as empty array, not undefined", async () => {
    writeFile(tmpDir, "src/app.ts", 'export const x = 1;\n');

    mockCreate.mockResolvedValue(mockTextResponse("[]"));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.errors).toBeDefined();
    expect(Array.isArray(report.errors)).toBe(true);
    expect(report.errors.length).toBe(0);
  });

  it("report has all expected fields with correct types", async () => {
    writeFile(tmpDir, "src/app.ts", 'export const x = 1;\n');

    mockCreate.mockResolvedValue(mockTextResponse("[]"));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(typeof report.timestamp).toBe("string");
    expect(typeof report.projectPath).toBe("string");
    expect(report.projectPath).toBe(tmpDir);
    expect(typeof report.filesScanned).toBe("number");
    expect(Array.isArray(report.findings)).toBe(true);
    expect(Array.isArray(report.errors)).toBe(true);
    expect(typeof report.summary).toBe("object");
    expect(report.summary).toHaveProperty("critical");
    expect(report.summary).toHaveProperty("high");
    expect(report.summary).toHaveProperty("medium");
    expect(report.summary).toHaveProperty("low");
    expect(report.summary).toHaveProperty("info");
    expect(typeof report.knowledgeBaseSize).toBe("number");
    expect(typeof report.model).toBe("string");
  });

  it("summary counts match findings array when scan succeeds", async () => {
    writeFile(tmpDir, "src/app.ts", 'export const x = 1;\n');

    const findings = [
      validFindingJSON({ severity: "critical", title: "A" }),
      validFindingJSON({ severity: "high", title: "B" }),
      validFindingJSON({ severity: "medium", title: "C", confidence: "medium" }),
    ];

    mockCreate.mockResolvedValue(mockTextResponse(JSON.stringify(findings)));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    const total =
      report.summary.critical +
      report.summary.high +
      report.summary.medium +
      report.summary.low +
      report.summary.info;
    expect(total).toBe(report.findings.length);
  });
});

// ─── Gated report behavior ──────────────────────────────────────────────────

describe("aiScan() — gated report behavior", () => {
  it("applies gate when gateConfig is provided", async () => {
    writeFile(tmpDir, "src/app.ts", 'export const x = 1;\n');

    const findings = [
      validFindingJSON({ severity: "critical", title: "Finding 1" }),
      validFindingJSON({ severity: "high", title: "Finding 2" }),
      validFindingJSON({ severity: "medium", title: "Finding 3", confidence: "medium" }),
    ];

    mockCreate.mockResolvedValue(mockTextResponse(JSON.stringify(findings)));

    const report = await aiScan(tmpDir, {
      apiKey: "test-key",
      gateConfig: { freeLimit: 1 },
    });

    expect(report.gate).toBeDefined();
    expect(report.gate!.isGated).toBe(true);
    expect(report.gate!.visible.length).toBe(1);
    expect(report.gate!.gated.length).toBe(2);
    // Visible findings on the report are the gated visible set
    expect(report.findings.length).toBe(1);
    // Summary still reflects all findings
    const total =
      report.summary.critical +
      report.summary.high +
      report.summary.medium +
      report.summary.low +
      report.summary.info;
    expect(total).toBe(3);
  });

  it("does not apply gate when gateConfig is not provided", async () => {
    writeFile(tmpDir, "src/app.ts", 'export const x = 1;\n');

    mockCreate.mockResolvedValue(mockTextResponse("[]"));

    const report = await aiScan(tmpDir, { apiKey: "test-key" });

    expect(report.gate).toBeUndefined();
  });
});
