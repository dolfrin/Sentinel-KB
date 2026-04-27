// Tests for src/triage.ts — verifies FP filters and severity downgrades
// based on real false positives seen in production audits.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { triageFindings } from "../triage.js";
import type { Finding } from "../scanner.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-triage-test-"));
});

afterEach(() => {
  if (tmpDir && fs.existsSync(tmpDir)) {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: "TEST-001",
    ruleName: "Test rule",
    severity: "critical",
    category: "Test",
    message: "test message",
    file: "src/foo.ts",
    line: 1,
    snippet: "",
    ...overrides,
  };
}

function writeFile(rel: string, content: string): void {
  const full = path.join(tmpDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, "utf-8");
}

// ─── Config file blocklist ─────────────────────────────────────

describe("triage: config files", () => {
  it("drops findings on google-services.json", () => {
    const findings = [makeFinding({ file: "app/google-services.json", ruleId: "SEC-009" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0].reason).toMatch(/config file/i);
  });

  it("drops findings on .env.example", () => {
    const findings = [makeFinding({ file: ".env.example", ruleId: "SEC-005" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
    expect(result.dropped).toHaveLength(1);
  });

  it("drops findings on yarn.lock", () => {
    const findings = [makeFinding({ file: "yarn.lock" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
  });

  it("keeps findings on regular source files", () => {
    writeFile("src/foo.ts", "const x = 1;\n");
    const findings = [makeFinding({ file: "src/foo.ts" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(1);
    expect(result.dropped).toHaveLength(0);
  });
});

// ─── Test path detection ──────────────────────────────────────

describe("triage: test paths", () => {
  it("downgrades severity for findings in test/ directory", () => {
    writeFile("test/auth_test.go", "package test\n");
    const findings = [makeFinding({ file: "test/auth_test.go", severity: "critical" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(1);
    expect(result.kept[0].severity).toBe("medium");
    expect(result.downgraded).toHaveLength(1);
  });

  it("downgrades for __tests__/", () => {
    writeFile("src/__tests__/foo.test.ts", "describe('x', () => {});\n");
    const findings = [makeFinding({ file: "src/__tests__/foo.test.ts", severity: "high" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("low");
  });

  it("downgrades for fixtures/", () => {
    writeFile("fixtures/bad.ts", "const x = 1;");
    const findings = [makeFinding({ file: "fixtures/bad.ts", severity: "critical" })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("medium");
  });
});

// ─── Inline test blocks ───────────────────────────────────────

describe("triage: inline test blocks (Rust #[cfg(test)])", () => {
  it("downgrades findings inside #[cfg(test)] mod tests block", () => {
    writeFile("src/lib.rs", `
pub fn real_code() {}

#[cfg(test)]
mod tests {
    fn helper() {
        let url = "postgres://user:secret@host/db";
    }
}
`);
    const findings = [makeFinding({
      file: "src/lib.rs",
      line: 7,
      severity: "critical",
      ruleId: "DB-003",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("medium");
    expect(result.downgraded[0].reason).toMatch(/inline test block/i);
  });

  it("keeps severity for findings outside the test block", () => {
    writeFile("src/lib.rs", `
pub fn real_code() {
    let url = "postgres://user:secret@host/db";
}

#[cfg(test)]
mod tests {
    fn ok() {}
}
`);
    const findings = [makeFinding({
      file: "src/lib.rs",
      line: 3,
      severity: "critical",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("critical");
  });

  it("downgrades findings in pub mod test_helpers", () => {
    writeFile("src/lib.rs", `
pub fn real() {}

pub mod test_helpers {
    pub fn fake_url() -> &'static str {
        "postgres://user:secret@host/test"
    }
}
`);
    const findings = [makeFinding({
      file: "src/lib.rs",
      line: 6,
      severity: "high",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("low");
  });
});

// ─── Per-rule filters ─────────────────────────────────────────

describe("triage: per-rule context filters", () => {
  it("E2E-003: downgrades ratchet calls inside withSessionLock", () => {
    writeFile("src/messenger.kt", `
fun sendMessage(contactId: String) {
    sessionManager.withSessionLock(contactId) {
        val encrypted = ratchetEncrypt(message)
        saveSession()
    }
}
`);
    const findings = [makeFinding({
      file: "src/messenger.kt",
      line: 4,
      ruleId: "E2E-003",
      severity: "critical",
      snippet: "val encrypted = ratchetEncrypt(message)",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept[0].severity).toBe("medium");
    expect(result.downgraded[0].reason).toMatch(/withSessionLock/);
  });

  it("MSG-001: drops generic notification strings", () => {
    const findings = [makeFinding({
      file: "src/notif.kt",
      ruleId: "MSG-001",
      snippet: 'val title = "You have a new encrypted message"',
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
    expect(result.dropped).toHaveLength(1);
  });

  it("MSG-001: keeps real content logging", () => {
    writeFile("src/notif.kt", "val text = body.plainText\n");
    const findings = [makeFinding({
      file: "src/notif.kt",
      ruleId: "MSG-001",
      snippet: "val text = body.plainText",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(1);
  });

  it("MSG-007: drops byte-count logging", () => {
    const findings = [makeFinding({
      ruleId: "MSG-007",
      snippet: 'tracing::info!("Vault file stored: ({} bytes)", body.len())',
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
  });

  it("AND-001: drops LAUNCHER activity export", () => {
    writeFile("AndroidManifest.xml", `<?xml version="1.0"?>
<manifest>
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>
`);
    const findings = [makeFinding({
      file: "AndroidManifest.xml",
      line: 4,
      ruleId: "AND-001",
      snippet: '<activity android:name=".MainActivity" android:exported="true">',
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/LAUNCHER/);
  });

  it("SRV-004: drops findings when file uses Axum extractor pattern", () => {
    writeFile("src/handlers/auth.rs", `
use axum::extract::*;

pub async fn login(
    AuthUser(user_id): AuthUser,
    Json(body): Json<LoginBody>,
) -> Result<...> {
    ...
}
`);
    const findings = [makeFinding({
      file: "src/handlers/auth.rs",
      line: 5,
      ruleId: "SRV-004",
    })];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(0);
  });
});

// ─── Statistics tracking ──────────────────────────────────────

describe("triage: statistics", () => {
  it("returns counts of dropped and downgraded", () => {
    writeFile("src/foo.ts", "x");
    writeFile("test/bar.ts", "x");
    const findings = [
      makeFinding({ file: "src/foo.ts" }),                              // kept
      makeFinding({ file: "test/bar.ts", severity: "critical" }),       // downgraded
      makeFinding({ file: ".env.example", severity: "critical" }),      // dropped
      makeFinding({ file: "google-services.json", ruleId: "SEC-009" }), // dropped
    ];
    const result = triageFindings(findings, tmpDir);
    expect(result.kept).toHaveLength(2);
    expect(result.dropped).toHaveLength(2);
    expect(result.downgraded).toHaveLength(1);
  });
});
