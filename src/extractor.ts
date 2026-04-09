// Extracts security findings from audit report PDFs
// Supports: Trail of Bits, Cure53, NCC Group, academic papers, generic formats

import * as fs from "fs";
import * as path from "path";

export interface ReportInfo {
  id: string;
  firm: string;
  target: string;
}

export interface ExtractedFinding {
  sourceId: string;
  firm: string;
  target: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  category: string;
  cwe?: string;
}

function parseSeverity(text: string): ExtractedFinding["severity"] {
  const lower = text.toLowerCase();
  if (lower.includes("critical")) return "critical";
  if (lower.includes("high")) return "high";
  if (lower.includes("medium") || lower.includes("moderate")) return "medium";
  if (lower.includes("low")) return "low";
  return "info";
}

function categorize(title: string, desc: string): string {
  const text = (title + " " + desc).toLowerCase();

  if (text.match(/ratchet|x3dh|olm|megolm|double.ratchet|session.key|prekey|signal.protocol/)) return "E2E Protocol";
  if (text.match(/encrypt|decrypt|cipher|aes|chacha|nonce|iv|padding|mac|hmac|signature|kdf|pbkdf|argon/)) return "Cryptography";
  if (text.match(/webrtc|ice|stun|turn|srtp|dtls|datachannel|sdp|peer.connection/)) return "WebRTC/P2P";
  if (text.match(/key.storage|keystore|keychain|plaintext.key|key.material|secret.storage/)) return "Key Management";
  if (text.match(/metadata|timing|side.channel|traffic.analysis|fingerprint/)) return "Metadata/Side Channel";
  if (text.match(/replay|reflect|inject|spoof|impersonat|forge/)) return "Message Integrity";
  if (text.match(/auth|login|session|token|jwt|oauth|permission|privilege|access.control/)) return "Authentication";
  if (text.match(/dos|denial|exhaust|flood|rate.limit|resource/)) return "Denial of Service";
  if (text.match(/memory|buffer|overflow|use.after.free|unsafe|pointer|heap|stack|oob|out.of.bound/)) return "Memory Safety";
  if (text.match(/backup|export|migration|storage|database|sqlite|sql/)) return "Data Storage";
  if (text.match(/notification|push|fcm|apns|alert/)) return "Notifications";
  if (text.match(/group|member|admin|room|channel/)) return "Group Security";
  if (text.match(/android|ios|mobile|apk|intent|manifest|webview|activity/)) return "Mobile Security";
  if (text.match(/server|api|endpoint|cors|header|tls|certificate|ssl/)) return "Server Security";
  if (text.match(/xss|injection|input|sanitiz|escap|html|csrf|ssrf/)) return "Input Validation";
  if (text.match(/privat|leak|expos|disclos|log|debug|pii/)) return "Information Disclosure";
  if (text.match(/smart.contract|solidity|evm|reentrancy|delegatecall|selfdestruct/)) return "Smart Contracts";
  if (text.match(/config|default|misconfigur|hardcoded|credential/)) return "Configuration";

  return "General";
}

/** Deduplicate findings by title similarity */
function dedup(findings: ExtractedFinding[]): ExtractedFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = f.title.toLowerCase().replace(/\s+/g, " ").trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Extract findings from PDF text using multiple audit report formats */
export function extractFindings(text: string, source: ReportInfo): ExtractedFinding[] {
  const findings: ExtractedFinding[] = [];

  // ─── Pattern 1: Universal finding ID format ───
  // Matches: TOB-XXX-NNN, MUL22-01, ATRS-01, CF-01, etc. followed by ":" or "—" and title
  // Covers: Trail of Bits, Atredis, Leviathan, Include Security, and similar firms
  const idPattern = /([A-Z]{2,8}\d{0,4}[-_][A-Z0-9]+-?\d*)\s*[:\-–—·]\s*(.+?)(?:\n|\r)/g;
  let match;
  while ((match = idPattern.exec(text)) !== null) {
    const title = match[2].trim();
    if (title.length < 5 || title.length > 200) continue;
    // Skip table of contents entries (just page numbers)
    if (/^\d+$/.test(title) || /^\.{3,}/.test(title)) continue;
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity: parseSeverity(context), title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // ─── Pattern 2: Cure53/7ASecurity BRP format ───
  // "BRP-01-001 Mobile: Title (Medium)" or "AVP-01-001 WP2: Title (Critical)"
  const brpPattern = /([A-Z]{2,6}-\d{2}-\d{2,4})\s+(?:[\w]+:\s+)?(.+?)\s*\((Critical|High|Medium|Low|Info(?:rmational)?)\)/gi;
  while ((match = brpPattern.exec(text)) !== null) {
    const title = match[2].trim();
    const severity = parseSeverity(match[3]);
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity, title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // ─── Pattern 3: NCC Group format ───
  // "Finding <Title>\nRisk <Severity> Impact: X, Exploitability: Y\nIdentifier NCC-XXX-NNN"
  const nccFindingPattern = /Finding\s+(.{5,150})\nRisk\s+(Critical|High|Medium|Low|Informational)/gi;
  while ((match = nccFindingPattern.exec(text)) !== null) {
    const title = match[1].trim();
    const severity = parseSeverity(match[2]);
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity, title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // ─── Pattern 4: "Issue N:" or "Vulnerability N:" ───
  const issuePattern = /(?:Issue|Vulnerability|Bug|Weakness|Defect)\s*(?:#?\d+|[A-Z])\s*[:\-–]\s*(.+?)(?:\n|\r)/gi;
  while ((match = issuePattern.exec(text)) !== null) {
    const title = match[1].trim();
    if (title.length < 5 || title.length > 200) continue;
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity: parseSeverity(context), title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // ─── Pattern 5: Severity-first format ───
  // "Severity: High\nTitle: Something bad"
  const sevFirstPattern = /(?:Severity|Risk|Rating|Impact)\s*[:\-]\s*(Critical|High|Medium|Moderate|Low|Info(?:rmational)?)\s*[\n\r]+\s*(?:Title|Name|Summary|Finding)\s*[:\-]\s*(.+?)(?:\n|\r)/gi;
  while ((match = sevFirstPattern.exec(text)) !== null) {
    const title = match[2].trim();
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity: parseSeverity(match[1]), title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // ─── Pattern 6: Title (Severity) on a single line ───
  // Common in Cure53 and others: "Something bad here (High)"
  // Only match lines that look like finding titles (start with capital, reasonable length)
  const titleSevPattern = /^([A-Z][A-Za-z\s\-:]{10,100})\s*\((Critical|High|Medium|Low|Info(?:rmational)?)\)\s*$/gm;
  while ((match = titleSevPattern.exec(text)) !== null) {
    const title = match[1].trim();
    const context = text.substring(match.index, match.index + 800);
    findings.push({
      sourceId: source.id, firm: source.firm, target: source.target,
      severity: parseSeverity(match[2]), title,
      description: context.substring(0, 300).trim(),
      category: categorize(title, context),
    });
  }

  // Attach CWE references
  const cwePattern = /CWE-(\d+)/g;
  const allCwes: { cwe: string; pos: number }[] = [];
  while ((match = cwePattern.exec(text)) !== null) {
    allCwes.push({ cwe: `CWE-${match[1]}`, pos: match.index });
  }
  // Attach CWE to the nearest preceding finding
  for (const cweRef of allCwes) {
    let closest: ExtractedFinding | null = null;
    let closestDist = Infinity;
    for (const f of findings) {
      const fPos = text.indexOf(f.title);
      if (fPos >= 0 && cweRef.pos > fPos && cweRef.pos - fPos < closestDist) {
        closestDist = cweRef.pos - fPos;
        closest = f;
      }
    }
    if (closest && closestDist < 2000) {
      closest.cwe = cweRef.cwe;
    }
  }

  return dedup(findings);
}

/** Parse a PDF file and extract findings */
export async function extractFromPdf(pdfPath: string, source: ReportInfo): Promise<ExtractedFinding[]> {
  const pdfModule = await import("pdf-parse");
  const PDFParse = (pdfModule as any).PDFParse;
  const buffer = new Uint8Array(fs.readFileSync(pdfPath));
  const parser = new PDFParse(buffer);
  await parser.load();
  const result = await parser.getText();
  return extractFindings(result.text, source);
}

/** Extract findings from all downloaded reports */
export async function extractAll(
  reports: { source: ReportInfo; path: string }[]
): Promise<{ findings: ExtractedFinding[]; errors: { id: string; error: string }[] }> {
  const allFindings: ExtractedFinding[] = [];
  const errors: { id: string; error: string }[] = [];

  for (const report of reports) {
    try {
      const findings = await extractFromPdf(report.path, report.source);
      allFindings.push(...findings);
      if (findings.length > 0) {
        console.log(`  ✓ ${report.source.id}: ${findings.length} findings`);
      }
    } catch (err: any) {
      errors.push({ id: report.source.id, error: err.message });
    }
  }

  return { findings: allFindings, errors };
}

/** Save extracted findings to JSON */
export function saveFindings(findings: ExtractedFinding[], outputPath: string) {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(findings, null, 2));
}

/** Load previously extracted findings */
export function loadFindings(filePath: string): ExtractedFinding[] {
  if (!fs.existsSync(filePath)) return [];
  return JSON.parse(fs.readFileSync(filePath, "utf-8"));
}
