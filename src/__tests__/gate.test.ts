// Unit tests for src/gate.ts (TDD — written before implementation)

import { describe, it, expect } from "vitest";
import { gateFindings, type GateConfig, type GatedResult } from "../gate.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface MockFinding {
  severity: string;
  category: string;
  title: string;
  description: string;
  recommendation: string;
  file: string;
  line: number;
}

function makeFinding(overrides: Partial<MockFinding> = {}): MockFinding {
  return {
    severity: "medium",
    category: "E2E Encryption",
    title: "Weak cipher used",
    description: "AES-ECB mode is deterministic and leaks patterns.",
    recommendation: "Use AES-GCM instead.",
    file: "src/crypto.ts",
    line: 42,
    ...overrides,
  };
}

function makeFindings(severities: string[]): MockFinding[] {
  return severities.map((sev, i) =>
    makeFinding({
      severity: sev,
      title: `Finding ${i + 1}`,
      file: `src/file${i + 1}.ts`,
      line: i + 1,
    })
  );
}

// ─── Under free limit — all visible ──────────────────────────────────────────

describe("gateFindings() — under free limit", () => {
  it("shows all findings when count equals free limit", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.visible.length).toBe(5);
    expect(result.gated.length).toBe(0);
    expect(result.isGated).toBe(false);
  });

  it("shows all findings when count is below free limit", () => {
    const findings = makeFindings(["high", "medium"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.visible.length).toBe(2);
    expect(result.gated.length).toBe(0);
    expect(result.isGated).toBe(false);
  });

  it("shows all findings when findings array is empty", () => {
    const result = gateFindings([], { freeLimit: 5 });
    expect(result.visible.length).toBe(0);
    expect(result.gated.length).toBe(0);
    expect(result.isGated).toBe(false);
  });

  it("uses default free limit of 5", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low"]);
    const result = gateFindings(findings);
    expect(result.visible.length).toBe(5);
    expect(result.isGated).toBe(false);
  });
});

// ─── Over free limit — gating applied ────────────────────────────────────────

describe("gateFindings() — over free limit", () => {
  it("gates findings beyond free limit", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "low", "low"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.visible.length).toBe(5);
    expect(result.gated.length).toBe(2);
    expect(result.isGated).toBe(true);
  });

  it("gated findings only show severity, category, title — not description, recommendation, file, line", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "medium", "high"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.gated.length).toBeGreaterThan(0);
    for (const g of result.gated) {
      // Must have these three fields
      expect(typeof g.severity).toBe("string");
      expect(typeof g.category).toBe("string");
      expect(typeof g.title).toBe("string");
      // Must NOT expose sensitive details
      expect((g as any).description).toBeUndefined();
      expect((g as any).recommendation).toBeUndefined();
      expect((g as any).file).toBeUndefined();
      expect((g as any).line).toBeUndefined();
    }
  });

  it("totalCount reflects the full number of findings including gated", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "medium", "critical"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.totalCount).toBe(7);
  });
});

// ─── Severity sorting — critical findings prioritised ─────────────────────────

describe("gateFindings() — severity prioritisation", () => {
  it("prioritizes critical findings in the visible set", () => {
    // 3 low + 1 critical + 1 high + 2 more low = 7 total, limit 5
    // visible should contain the critical and high findings
    const findings = makeFindings(["low", "low", "low", "critical", "high", "low", "low"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    const visibleSeverities = result.visible.map((f) => (f as MockFinding).severity);
    expect(visibleSeverities).toContain("critical");
    expect(visibleSeverities).toContain("high");
  });

  it("sorts visible findings critical > high > medium > low > info", () => {
    const findings = makeFindings(["info", "low", "medium", "high", "critical", "critical", "high"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    for (let i = 1; i < result.visible.length; i++) {
      const prev = order[(result.visible[i - 1] as MockFinding).severity];
      const curr = order[(result.visible[i] as MockFinding).severity];
      expect(prev).toBeLessThanOrEqual(curr);
    }
  });

  it("lower severity findings end up gated when higher ones fill the visible set", () => {
    // 6 findings: 5 critical + 1 low; limit 5 — the low one should be gated
    const findings = makeFindings(["low", "critical", "critical", "critical", "critical", "critical"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    const gatedSeverities = result.gated.map((g) => g.severity);
    expect(gatedSeverities).toContain("low");
    // No critical should be gated
    expect(gatedSeverities).not.toContain("critical");
  });
});

// ─── Gate message ─────────────────────────────────────────────────────────────

describe("gateFindings() — gate message", () => {
  it("includes gate message when findings are gated", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "medium"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.gateMessage).toBeDefined();
    expect(typeof result.gateMessage).toBe("string");
    expect(result.gateMessage!.length).toBeGreaterThan(0);
  });

  it("gate message mentions the count of gated findings", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "medium", "high"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    // 2 findings gated — message should reference "2"
    expect(result.gateMessage).toContain("2");
  });

  it("gate message includes upgrade URL", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "low"]);
    const result = gateFindings(findings, {
      freeLimit: 5,
      upgradeUrl: "https://example.com/upgrade",
    });
    expect(result.gateMessage).toContain("https://example.com/upgrade");
  });

  it("uses default upgrade URL when none provided", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "low"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.gateMessage).toContain("https://sentinel-kb.dev/upgrade");
  });

  it("no gate message when not gated", () => {
    const findings = makeFindings(["medium", "high"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.gateMessage).toBeUndefined();
  });
});

// ─── totalCount ───────────────────────────────────────────────────────────────

describe("gateFindings() — totalCount", () => {
  it("totalCount equals findings length when not gated", () => {
    const findings = makeFindings(["low", "medium", "high"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.totalCount).toBe(3);
  });

  it("totalCount equals findings length when gated", () => {
    const findings = makeFindings(["low", "low", "low", "low", "low", "low", "low"]);
    const result = gateFindings(findings, { freeLimit: 5 });
    expect(result.totalCount).toBe(7);
    expect(result.visible.length + result.gated.length).toBe(7);
  });
});

// ─── Custom freeLimit ─────────────────────────────────────────────────────────

describe("gateFindings() — custom freeLimit", () => {
  it("respects freeLimit of 1", () => {
    const findings = makeFindings(["high", "medium", "low"]);
    const result = gateFindings(findings, { freeLimit: 1 });
    expect(result.visible.length).toBe(1);
    expect(result.gated.length).toBe(2);
    expect(result.isGated).toBe(true);
  });

  it("respects freeLimit of 0 — all findings gated", () => {
    const findings = makeFindings(["high", "medium"]);
    const result = gateFindings(findings, { freeLimit: 0 });
    expect(result.visible.length).toBe(0);
    expect(result.gated.length).toBe(2);
    expect(result.isGated).toBe(true);
  });

  it("respects large freeLimit — nothing gated", () => {
    const findings = makeFindings(["high", "medium", "low"]);
    const result = gateFindings(findings, { freeLimit: 100 });
    expect(result.visible.length).toBe(3);
    expect(result.gated.length).toBe(0);
    expect(result.isGated).toBe(false);
  });
});
