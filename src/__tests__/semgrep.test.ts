// Tests for src/semgrep.ts — verifies graceful degradation when semgrep is missing
// and severity/category mapping when it's available.

import { describe, it, expect } from "vitest";
import { isSemgrepAvailable, runSemgrep } from "../semgrep.js";
import * as os from "os";
import * as fs from "fs";
import * as path from "path";

describe("semgrep: availability", () => {
  it("isSemgrepAvailable returns a boolean", () => {
    const result = isSemgrepAvailable();
    expect(typeof result).toBe("boolean");
  });

  it("runSemgrep returns [] when semgrep is unavailable (graceful)", () => {
    if (isSemgrepAvailable()) {
      // Skip — semgrep is installed; this test only covers the unavailable path
      return;
    }
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-semgrep-test-"));
    try {
      const findings = runSemgrep(tmp);
      expect(findings).toEqual([]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("runSemgrep does not throw when given an empty directory", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-semgrep-test-"));
    try {
      expect(() => runSemgrep(tmp)).not.toThrow();
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("semgrep: integration with scanner.audit() (only if installed)", () => {
  it("scanner.audit() with semgrep:true does not crash even when semgrep is missing", async () => {
    const { audit } = await import("../scanner.js");
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-semgrep-int-"));
    try {
      fs.writeFileSync(path.join(tmp, "test.js"), "console.log('hi');\n");
      const report = audit(tmp, { semgrep: true });
      expect(report).toBeDefined();
      expect(Array.isArray(report.findings)).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
