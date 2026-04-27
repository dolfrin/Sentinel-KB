// Tests for src/ai-triage.ts — verifies graceful behaviour without API key,
// recalibrateSeverity, and basic shape of the result type.
//
// Live Claude calls are not exercised here — they would require a real key and
// would burn credits on every CI run. Integration is verified by the type system
// and by the recalibrateSeverity helper, which has no I/O.

import { describe, it, expect } from "vitest";
import { aiTriageFindings, recalibrateSeverity } from "../ai-triage.js";
import type { Finding } from "../scanner.js";

function f(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "TEST-001",
    ruleName: "Test",
    severity: "critical",
    category: "Test",
    message: "msg",
    file: "src/foo.ts",
    line: 1,
    snippet: "",
    ...overrides,
  };
}

describe("aiTriageFindings: graceful degradation", () => {
  it("returns kept=findings and ran=false when no API key is provided", async () => {
    const findings = [f(), f({ ruleId: "TEST-002" })];
    const result = await aiTriageFindings(findings, "/tmp", { apiKey: undefined });
    // Without key, the function falls back to env — but we explicitly clear it for this test
    const originalKey = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      const r = await aiTriageFindings(findings, "/tmp");
      expect(r.ran).toBe(false);
      expect(r.kept).toEqual(findings);
      expect(r.rejected).toEqual([]);
      expect(r.costUsd).toBe(0);
    } finally {
      if (originalKey !== undefined) process.env.ANTHROPIC_API_KEY = originalKey;
    }
    expect(result).toBeDefined();
  });

  it("returns ran=false for empty findings list (no API call)", async () => {
    const result = await aiTriageFindings([], "/tmp", { apiKey: "sk-fake" });
    expect(result.ran).toBe(false);
    expect(result.kept).toEqual([]);
    expect(result.costUsd).toBe(0);
  });
});

describe("recalibrateSeverity", () => {
  it("keeps severity when confidence >= 70", () => {
    const findings = [f({ severity: "critical" })];
    const verdicts = [{
      ruleId: "TEST-001", file: "src/foo.ts", line: 1,
      isReal: true, confidence: 85, reasoning: "strong",
    }];
    const result = recalibrateSeverity(findings, verdicts);
    expect(result[0].severity).toBe("critical");
  });

  it("downgrades by 1 when confidence between 50 and 70", () => {
    const findings = [f({ severity: "critical" })];
    const verdicts = [{
      ruleId: "TEST-001", file: "src/foo.ts", line: 1,
      isReal: true, confidence: 60, reasoning: "weak",
    }];
    const result = recalibrateSeverity(findings, verdicts);
    expect(result[0].severity).toBe("high");
  });

  it("downgrades by 2 when confidence below 50", () => {
    const findings = [f({ severity: "critical" })];
    const verdicts = [{
      ruleId: "TEST-001", file: "src/foo.ts", line: 1,
      isReal: false, confidence: 30, reasoning: "FP",
    }];
    const result = recalibrateSeverity(findings, verdicts);
    expect(result[0].severity).toBe("medium");
  });

  it("keeps severity unchanged when no matching verdict", () => {
    const findings = [f({ severity: "high" })];
    const verdicts: any[] = [];
    const result = recalibrateSeverity(findings, verdicts);
    expect(result[0].severity).toBe("high");
  });

  it("does not mutate the input findings array", () => {
    const findings = [f({ severity: "critical" })];
    const verdicts = [{
      ruleId: "TEST-001", file: "src/foo.ts", line: 1,
      isReal: true, confidence: 60, reasoning: "weak",
    }];
    recalibrateSeverity(findings, verdicts);
    expect(findings[0].severity).toBe("critical");
  });
});
