// Unit tests for src/rules.ts
// Validates rule structure, uniqueness, regex compilability, and semantic correctness.

import { describe, it, expect } from "vitest";
import {
  allRules,
  e2eRules,
  webrtcRules,
  messengerRules,
  androidRules,
  backendRules,
  injectionRules,
  xssRules,
  authRules,
  secretsRules,
  ssrfCsrfRules,
  memorySafetyRules,
  concurrencyRules,
  dependencyRules,
  type Rule,
  type Severity,
} from "../rules.js";

const VALID_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

// ─── allRules composition ─────────────────────────────────────────────────────

describe("allRules", () => {
  it("is a non-empty array", () => {
    expect(Array.isArray(allRules)).toBe(true);
    expect(allRules.length).toBeGreaterThan(0);
  });

  it("contains all category sub-arrays", () => {
    const allIds = new Set(allRules.map((r) => r.id));
    for (const rule of [...e2eRules, ...webrtcRules, ...messengerRules, ...androidRules, ...backendRules, ...injectionRules, ...xssRules, ...authRules, ...secretsRules, ...ssrfCsrfRules, ...memorySafetyRules, ...concurrencyRules, ...dependencyRules]) {
      expect(allIds.has(rule.id)).toBe(true);
    }
  });

  it("total count equals sum of category arrays", () => {
    const total =
      e2eRules.length +
      webrtcRules.length +
      messengerRules.length +
      androidRules.length +
      backendRules.length +
      injectionRules.length +
      xssRules.length +
      authRules.length +
      secretsRules.length +
      ssrfCsrfRules.length +
      memorySafetyRules.length +
      concurrencyRules.length +
      dependencyRules.length;
    expect(allRules.length).toBe(total);
  });
});

// ─── Required fields ──────────────────────────────────────────────────────────

describe("every rule has required fields", () => {
  it("each rule has a non-empty id string", () => {
    for (const rule of allRules) {
      expect(typeof rule.id).toBe("string");
      expect(rule.id.length).toBeGreaterThan(0);
    }
  });

  it("each rule has a non-empty name string", () => {
    for (const rule of allRules) {
      expect(typeof rule.name).toBe("string");
      expect(rule.name.length).toBeGreaterThan(0);
    }
  });

  it("each rule has a non-empty description string", () => {
    for (const rule of allRules) {
      expect(typeof rule.description).toBe("string");
      expect(rule.description.length).toBeGreaterThan(0);
    }
  });

  it("each rule has a valid severity", () => {
    for (const rule of allRules) {
      expect(VALID_SEVERITIES).toContain(rule.severity);
    }
  });

  it("each rule has a non-empty category string", () => {
    for (const rule of allRules) {
      expect(typeof rule.category).toBe("string");
      expect(rule.category.length).toBeGreaterThan(0);
    }
  });

  it("each rule has a non-empty filePatterns array", () => {
    for (const rule of allRules) {
      expect(Array.isArray(rule.filePatterns)).toBe(true);
      expect(rule.filePatterns.length).toBeGreaterThan(0);
    }
  });

  it("each rule has at least one of badPatterns or requiredPatterns", () => {
    for (const rule of allRules) {
      const hasBad = Array.isArray(rule.badPatterns) && rule.badPatterns.length > 0;
      const hasRequired = Array.isArray(rule.requiredPatterns) && rule.requiredPatterns.length > 0;
      expect(hasBad || hasRequired).toBe(true);
    }
  });
});

// ─── No duplicate IDs ─────────────────────────────────────────────────────────

describe("rule IDs are unique", () => {
  it("no two rules share the same id", () => {
    const ids = allRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});

// ─── Regex patterns compile and work ─────────────────────────────────────────

describe("all regex patterns are valid RegExp instances", () => {
  it("badPatterns entries are RegExp instances with a message", () => {
    for (const rule of allRules) {
      if (!rule.badPatterns) continue;
      for (const bp of rule.badPatterns) {
        expect(bp.pattern).toBeInstanceOf(RegExp);
        expect(typeof bp.message).toBe("string");
        expect(bp.message.length).toBeGreaterThan(0);
        // Verify the pattern doesn't throw on a test string
        expect(() => bp.pattern.test("test string")).not.toThrow();
      }
    }
  });

  it("requiredPatterns entries are RegExp instances with a message and filePattern", () => {
    for (const rule of allRules) {
      if (!rule.requiredPatterns) continue;
      for (const rp of rule.requiredPatterns) {
        expect(rp.pattern).toBeInstanceOf(RegExp);
        expect(typeof rp.message).toBe("string");
        expect(rp.message.length).toBeGreaterThan(0);
        expect(typeof rp.filePattern).toBe("string");
        expect(rp.filePattern.length).toBeGreaterThan(0);
        expect(() => rp.pattern.test("test string")).not.toThrow();
      }
    }
  });
});

// ─── Category sub-arrays have correct categories ──────────────────────────────

describe("category sub-arrays contain rules with expected category values", () => {
  it("e2eRules all have category 'E2E Encryption'", () => {
    for (const rule of e2eRules) {
      expect(rule.category).toBe("E2E Encryption");
    }
  });

  it("webrtcRules all have category 'WebRTC/P2P'", () => {
    for (const rule of webrtcRules) {
      expect(rule.category).toBe("WebRTC/P2P");
    }
  });

  it("messengerRules all have category 'Messenger'", () => {
    for (const rule of messengerRules) {
      expect(rule.category).toBe("Messenger");
    }
  });

  it("androidRules all have category 'Android'", () => {
    for (const rule of androidRules) {
      expect(rule.category).toBe("Android");
    }
  });

  it("backendRules all have category 'Backend'", () => {
    for (const rule of backendRules) {
      expect(rule.category).toBe("Backend");
    }
  });
});

// ─── Rule ID prefixes match category ─────────────────────────────────────────

describe("rule ID prefixes match their category", () => {
  it("e2eRules use E2E- prefix", () => {
    for (const rule of e2eRules) {
      expect(rule.id.startsWith("E2E-")).toBe(true);
    }
  });

  it("webrtcRules use P2P- prefix", () => {
    for (const rule of webrtcRules) {
      expect(rule.id.startsWith("P2P-")).toBe(true);
    }
  });

  it("messengerRules use MSG- prefix", () => {
    for (const rule of messengerRules) {
      expect(rule.id.startsWith("MSG-")).toBe(true);
    }
  });

  it("androidRules use AND- prefix", () => {
    for (const rule of androidRules) {
      expect(rule.id.startsWith("AND-")).toBe(true);
    }
  });

  it("backendRules use SRV- prefix", () => {
    for (const rule of backendRules) {
      expect(rule.id.startsWith("SRV-")).toBe(true);
    }
  });
});

// ─── Spot-check specific known rules ─────────────────────────────────────────

describe("spot-check known rules", () => {
  it("E2E-002 detects hardcoded encryption key", () => {
    const rule = allRules.find((r) => r.id === "E2E-002")!;
    expect(rule).toBeDefined();
    // Should match: const aesKey = "AAAAAAAAAAAAAAAA"
    const matchingLine = 'const aesKey = "AAAAAAAAAAAAAAAA";';
    const matches = rule.badPatterns!.some((bp) => bp.pattern.test(matchingLine));
    expect(matches).toBe(true);
  });

  it("AND-002 detects cleartext traffic flag", () => {
    const rule = allRules.find((r) => r.id === "AND-002")!;
    expect(rule).toBeDefined();
    const matchingLine = 'android:usesCleartextTraffic="true"';
    const matches = rule.badPatterns!.some((bp) => bp.pattern.test(matchingLine));
    expect(matches).toBe(true);
  });

  it("SRV-003 detects SQL injection via format!", () => {
    const rule = allRules.find((r) => r.id === "SRV-003")!;
    expect(rule).toBeDefined();
    const matchingLine = 'let q = format!("SELECT * FROM users WHERE id = {}", user_id);';
    const matches = rule.badPatterns!.some((bp) => bp.pattern.test(matchingLine));
    expect(matches).toBe(true);
  });

  it("AND-005 detects WebView JavaScript enabled", () => {
    const rule = allRules.find((r) => r.id === "AND-005")!;
    expect(rule).toBeDefined();
    const matchingLine = "webView.settings.javaScriptEnabled = true";
    const matches = rule.badPatterns!.some((bp) => bp.pattern.test(matchingLine));
    expect(matches).toBe(true);
  });

  it("SRV-006 detects CORS wildcard origin", () => {
    const rule = allRules.find((r) => r.id === "SRV-006")!;
    expect(rule).toBeDefined();
    const matchingLine = ".allow_origin(Any)";
    const matches = rule.badPatterns!.some((bp) => bp.pattern.test(matchingLine));
    expect(matches).toBe(true);
  });
});
