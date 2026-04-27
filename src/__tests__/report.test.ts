// Tests for src/report.ts — verifies text, JSON, SARIF formatters.

import { describe, it, expect } from "vitest";
import { formatText, formatJSON, formatSARIF } from "../report.js";
import type { AuditReport, Issue } from "../scanner.js";

function makeIssue(overrides: Partial<Issue> = {}): Issue {
  const occ = { file: "src/foo.ts", line: 10, snippet: "const x = 1;", message: "bad" };
  return {
    ruleId: "TEST-001",
    ruleName: "Test rule",
    severity: "critical",
    category: "Test",
    message: "Test message",
    occurrences: [occ],
    displayedOccurrences: [occ],
    totalOccurrences: 1,
    ...overrides,
  };
}

function makeReport(issues: Issue[]): AuditReport {
  return {
    timestamp: "2026-04-27T00:00:00Z",
    projectPath: "/tmp/test",
    totalFiles: 5,
    findings: [],
    issues,
    summary: {
      critical: issues.filter(i => i.severity === "critical").length,
      high: issues.filter(i => i.severity === "high").length,
      medium: issues.filter(i => i.severity === "medium").length,
      low: issues.filter(i => i.severity === "low").length,
      info: issues.filter(i => i.severity === "info").length,
    },
    categories: {},
    totalIssues: issues.length,
  };
}

describe("formatText", () => {
  it("renders header with severity counts", () => {
    const report = makeReport([makeIssue()]);
    const out = formatText(report);
    expect(out).toContain("Sentinel-KB Security Audit");
    expect(out).toContain("Files:    5 scanned");
    expect(out).toContain("[TEST-001]");
  });

  it("shows clean run when no issues", () => {
    const out = formatText(makeReport([]));
    expect(out).toContain("No findings");
    expect(out).toContain("Clean run");
  });

  it("shows triage stats when present", () => {
    const report = makeReport([makeIssue()]);
    report.triage = { droppedCount: 5, downgradedCount: 3, decisions: [] };
    const out = formatText(report);
    expect(out).toContain("-5 false positives");
    expect(out).toContain("3 severity downgrades");
  });

  it("includes AI verdict when provided", () => {
    const report = makeReport([makeIssue()]);
    const out = formatText(report, {
      aiVerdicts: [{
        ruleId: "TEST-001", file: "src/foo.ts", line: 10,
        isReal: true, confidence: 92, reasoning: "looks bad",
      }],
    });
    expect(out).toContain("AI: ✓ Real (92%)");
    expect(out).toContain("looks bad");
  });

  it("groups issues by category", () => {
    const out = formatText(makeReport([
      makeIssue({ category: "Cryptography" }),
      makeIssue({ ruleId: "TEST-002", category: "Authentication" }),
    ]));
    expect(out).toContain("── Cryptography");
    expect(out).toContain("── Authentication");
  });
});

describe("formatJSON", () => {
  it("returns valid JSON containing the report", () => {
    const report = makeReport([makeIssue()]);
    const out = formatJSON(report);
    const parsed = JSON.parse(out);
    expect(parsed.totalIssues).toBe(1);
    expect(parsed.issues[0].ruleId).toBe("TEST-001");
  });

  it("includes aiVerdict when enrichment provides it", () => {
    const report = makeReport([makeIssue()]);
    const out = formatJSON(report, {
      aiVerdicts: [{
        ruleId: "TEST-001", file: "src/foo.ts", line: 10,
        isReal: false, confidence: 30, reasoning: "FP",
      }],
    });
    const parsed = JSON.parse(out);
    expect(parsed.issues[0].aiVerdict.isReal).toBe(false);
  });
});

describe("formatSARIF", () => {
  it("emits SARIF 2.1.0 with tool driver", () => {
    const out = formatSARIF(makeReport([makeIssue()]));
    const parsed = JSON.parse(out);
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0].tool.driver.name).toBe("sentinel-kb");
    expect(parsed.runs[0].results).toHaveLength(1);
  });

  it("maps severity to SARIF level (critical → error)", () => {
    const out = formatSARIF(makeReport([
      makeIssue({ severity: "critical" }),
      makeIssue({ ruleId: "T2", severity: "low" }),
    ]));
    const parsed = JSON.parse(out);
    const levels = parsed.runs[0].results.map((r: any) => r.level);
    expect(levels).toContain("error");
    expect(levels).toContain("note");
  });

  it("adds physical locations with line numbers", () => {
    const out = formatSARIF(makeReport([makeIssue()]));
    const parsed = JSON.parse(out);
    const loc = parsed.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe("src/foo.ts");
    expect(loc.region.startLine).toBe(10);
  });

  it("attaches AI properties when verdicts provided", () => {
    const report = makeReport([makeIssue()]);
    const out = formatSARIF(report, {
      aiVerdicts: [{
        ruleId: "TEST-001", file: "src/foo.ts", line: 10,
        isReal: true, confidence: 88, reasoning: "real",
      }],
    });
    const parsed = JSON.parse(out);
    expect(parsed.runs[0].results[0].properties.aiConfidence).toBe(88);
    expect(parsed.runs[0].results[0].properties.aiIsReal).toBe(true);
  });

  it("emits one rule entry per unique ruleId", () => {
    const out = formatSARIF(makeReport([
      makeIssue({ ruleId: "R1" }),
      makeIssue({ ruleId: "R1" }),
      makeIssue({ ruleId: "R2" }),
    ]));
    const parsed = JSON.parse(out);
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(2);
  });
});
