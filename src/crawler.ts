// Auto-discover ALL security audit reports from public sources
// Master source: juliocesarfort/public-pentesting-reports (83 firms)
// Plus: Trail of Bits GitHub, Cure53 website

import * as https from "https";
import * as http from "http";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

export interface DiscoveredReport {
  id: string;
  firm: string;
  target: string;
  url: string;
  filename: string;
  year: number;
}

// GitHub token raises rate limit from 60 to 5000 req/h (optional)
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";

function githubHeaders(): Record<string, string> {
  const h: Record<string, string> = { "User-Agent": "security-audit-kb/0.1", Accept: "application/json" };
  if (GITHUB_TOKEN) h["Authorization"] = `token ${GITHUB_TOKEN}`;
  return h;
}

/** Fetch text from URL, following redirects */
function fetchText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const doRequest = (currentUrl: string, depth: number) => {
      if (depth > 10) { reject(new Error("Too many redirects")); return; }
      const isGitHub = currentUrl.includes("github.com") || currentUrl.includes("githubusercontent.com");
      const headers = isGitHub ? githubHeaders() : { "User-Agent": "security-audit-kb/0.1", Accept: "application/json" };
      const c = currentUrl.startsWith("https") ? https : http;
      c.get(currentUrl, { headers }, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          const loc = res.headers.location;
          doRequest(loc.startsWith("http") ? loc : new URL(loc, currentUrl).href, depth + 1);
          return;
        }
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => resolve(data));
      }).on("error", reject);
    };
    doRequest(url, 0);
  });
}

async function fetchJson(url: string): Promise<any> {
  return JSON.parse(await fetchText(url));
}

/** Extract readable target name from filename */
function filenameToTarget(filename: string): string {
  return filename
    .replace(/\.pdf$/i, "")
    .replace(/^\d{4}-\d{2}-\d{2}[-_]/, "")
    .replace(/^\d{4}-\d{2}-/, "")
    .replace(/-securityreview$/i, "")
    .replace(/-fixreview$/i, "")
    .replace(/-threatmodel$/i, "")
    .replace(/^pentest-report_/i, "")
    .replace(/^audit-report_/i, "")
    .replace(/^review-report_/i, "")
    .replace(/^summary-report_/i, "")
    .replace(/_/g, " ")
    .replace(/-/g, " ")
    .replace(/\bv\d+\.\d+$/i, "")
    .replace(/\b(report|public|final)\b/gi, "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function extractYear(filename: string): number {
  const m = filename.match(/(\d{4})/);
  return m ? parseInt(m[1]) : 2022;
}

function makeId(firm: string, filename: string): string {
  const prefix = firm.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").substring(0, 20);
  const name = filename.replace(/\.pdf$/i, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").substring(0, 60);
  return `${prefix}-${name}`;
}

// ─────────────────────────────────────────────────────────────
// Source 1: Master repo — 83 audit firms
// github.com/juliocesarfort/public-pentesting-reports
//
// Strategy: git clone --depth 1 (no API rate limit) with fallback to API.
// Clone uses SSH if available, HTTPS otherwise.
// ─────────────────────────────────────────────────────────────

const MASTER_REPO = "juliocesarfort/public-pentesting-reports";
const MASTER_API = `https://api.github.com/repos/${MASTER_REPO}/contents`;
const MASTER_CLONE_SSH = `git@github.com:${MASTER_REPO}.git`;
const MASTER_CLONE_HTTPS = `https://github.com/${MASTER_REPO}.git`;

/** Sleep helper */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Clone repo (no checkout) and use `git ls-tree` to list PDF files.
 * Downloads 0 bytes of PDF content — just the tree metadata.
 */
function crawlViaGitClone(repoUrl: string, label: string, owner: string): DiscoveredReport[] {
  const cacheDir = path.join(process.env.HOME || "/tmp", ".security-audit-kb", ".clone-cache");
  const tmpDir = path.join(cacheDir, label);
  const reports: DiscoveredReport[] = [];

  try {
    fs.mkdirSync(cacheDir, { recursive: true });

    if (fs.existsSync(path.join(tmpDir, "HEAD")) || fs.existsSync(path.join(tmpDir, ".git"))) {
      // Already cloned — fetch latest
      const gitDir = fs.existsSync(path.join(tmpDir, "HEAD")) ? tmpDir : path.join(tmpDir, ".git");
      execSync(`git --git-dir="${gitDir}" fetch --depth 1 origin 2>/dev/null || true`, { timeout: 30000, stdio: "pipe" });
    } else {
      // Bare clone — no file checkout, just tree objects
      fs.rmSync(tmpDir, { recursive: true, force: true });
      execSync(`git clone --bare --depth 1 "${repoUrl}" "${tmpDir}"`, { timeout: 60000, stdio: "pipe" });
    }

    // List all files via git ls-tree (no checkout needed)
    const gitDir = fs.existsSync(path.join(tmpDir, "HEAD")) ? tmpDir : path.join(tmpDir, ".git");
    const output = execSync(`git --git-dir="${gitDir}" ls-tree -r --name-only HEAD`, { timeout: 15000, stdio: "pipe", maxBuffer: 10 * 1024 * 1024 }).toString();

    for (const line of output.split("\n")) {
      if (!line.toLowerCase().endsWith(".pdf")) continue;
      const parts = line.split("/");
      if (parts.length < 2) continue;
      const firmName = parts[0];
      const pdfName = parts[parts.length - 1];
      const downloadUrl = `https://raw.githubusercontent.com/${owner}/main/${parts.map(encodeURIComponent).join("/")}`;
      reports.push({
        id: makeId(firmName, pdfName),
        firm: firmName.replace(/([a-z])([A-Z])/g, "$1 $2"),
        target: filenameToTarget(pdfName),
        url: downloadUrl,
        filename: pdfName,
        year: extractYear(pdfName),
      });
    }
  } catch (err: any) {
    console.error(`[sentinel-kb] Git clone failed for ${label}: ${err.message}`);
  }

  return reports;
}

/** Crawl master repo via API (fallback when git is unavailable) */
async function crawlMasterRepoViaAPI(progress?: (msg: string) => void): Promise<DiscoveredReport[]> {
  const reports: DiscoveredReport[] = [];
  const log = progress || console.log;

  try {
    const contents = await fetchJson(MASTER_API);
    const firms = contents
      .filter((item: any) => item.type === "dir")
      .map((item: any) => ({ name: item.name, path: item.path }));
    log(`  Found ${firms.length} firms via API`);

    for (let i = 0; i < firms.length; i += 3) {
      const batch = firms.slice(i, i + 3);
      const results = await Promise.all(
        batch.map(async (firm: { name: string; path: string }) => {
          try {
            const pdfs = await fetchJson(`${MASTER_API}/${encodeURIComponent(firm.path)}`);
            return pdfs
              .filter((item: any) => item.type === "file" && item.name.toLowerCase().endsWith(".pdf"))
              .map((item: any) => ({
                id: makeId(firm.name, item.name),
                firm: firm.name.replace(/([a-z])([A-Z])/g, "$1 $2"),
                target: filenameToTarget(item.name),
                url: item.download_url,
                filename: item.name,
                year: extractYear(item.name),
              }));
          } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            console.error(`[sentinel-kb] Failed to crawl firm ${firm.path}: ${msg}`);
            return [];
          }
        })
      );
      for (const firmReports of results) reports.push(...firmReports);
      if (i + 3 < firms.length) await sleep(2000);
    }
  } catch (err: any) {
    log(`  Failed to crawl master repo via API: ${err.message}`);
  }

  return reports;
}

/**
 * Crawl the master repo — all 83 firms.
 * Tries git clone first (no rate limit), falls back to API.
 */
export async function crawlMasterRepo(progress?: (msg: string) => void): Promise<DiscoveredReport[]> {
  const log = progress || console.log;

  // Try git clone first — no API rate limit
  let hasGit = false;
  try { execSync("git --version", { stdio: "pipe" }); hasGit = true; } catch {}

  if (hasGit) {
    // Try SSH first, then HTTPS
    log(`  Using git clone (no API rate limit)...`);
    let reports = crawlViaGitClone(MASTER_CLONE_SSH, "master-repo", MASTER_REPO);
    if (reports.length === 0) {
      log(`  SSH clone failed, trying HTTPS...`);
      reports = crawlViaGitClone(MASTER_CLONE_HTTPS, "master-repo", MASTER_REPO);
    }
    if (reports.length > 0) {
      log(`  Found ${reports.length} reports from ${new Set(reports.map(r => r.firm)).size} firms`);
      return reports;
    }
    log(`  Git clone returned 0 reports, falling back to API...`);
  }

  return crawlMasterRepoViaAPI(progress);
}

// ─────────────────────────────────────────────────────────────
// Source 2: Trail of Bits — official publications repo
// ─────────────────────────────────────────────────────────────

export async function crawlTrailOfBits(): Promise<DiscoveredReport[]> {
  // Try git clone first
  let hasGit = false;
  try { execSync("git --version", { stdio: "pipe" }); hasGit = true; } catch {}

  if (hasGit) {
    const cloneReports = crawlViaGitClone("git@github.com:trailofbits/publications.git", "tob-publications", "trailofbits/publications");
    // Filter to only reviews/ directory
    const reviews = cloneReports.filter((r) => r.url.includes("/reviews/"));
    if (reviews.length > 0) return reviews;

    // Try HTTPS
    const httpsReports = crawlViaGitClone("https://github.com/trailofbits/publications.git", "tob-publications", "trailofbits/publications");
    const httpsReviews = httpsReports.filter((r) => r.url.includes("/reviews/"));
    if (httpsReviews.length > 0) return httpsReviews;
  }

  // Fallback to API
  const reports: DiscoveredReport[] = [];
  try {
    const contents = await fetchJson(
      "https://api.github.com/repos/trailofbits/publications/contents/reviews"
    );
    for (const item of contents) {
      if (!item.name.endsWith(".pdf")) continue;
      reports.push({
        id: makeId("tob", item.name),
        firm: "Trail of Bits",
        target: filenameToTarget(item.name),
        url: item.download_url,
        filename: item.name,
        year: extractYear(item.name),
      });
    }
  } catch (err: any) {
    console.error(`  Failed to crawl Trail of Bits: ${err.message}`);
  }
  return reports;
}

// ─────────────────────────────────────────────────────────────
// Source 3: Cure53 — website scrape
// ─────────────────────────────────────────────────────────────

export async function crawlCure53(): Promise<DiscoveredReport[]> {
  const reports: DiscoveredReport[] = [];
  try {
    const html = await fetchText("https://cure53.de/");
    const pdfPattern = /href="([^"]*\.pdf)"/gi;
    const seen = new Set<string>();
    let match;
    while ((match = pdfPattern.exec(html)) !== null) {
      const filename = match[1];
      if (filename.startsWith("http") && !filename.includes("cure53.de")) continue;
      if (seen.has(filename)) continue;
      seen.add(filename);
      const url = filename.startsWith("http") ? filename : `https://cure53.de/${filename}`;
      reports.push({
        id: makeId("cure53", filename),
        firm: "Cure53",
        target: filenameToTarget(filename),
        url,
        filename,
        year: extractYear(filename),
      });
    }
  } catch (err: any) {
    console.error(`  Failed to crawl Cure53: ${err.message}`);
  }
  return reports;
}

// ─────────────────────────────────────────────────────────────
// Source 4: Known direct URLs — academic papers, special reports
// ─────────────────────────────────────────────────────────────

export function getKnownReports(): DiscoveredReport[] {
  return [
    {
      id: "acad-matrix-megolm-2023",
      firm: "Ruhr University / Kings College",
      target: "Matrix Megolm",
      url: "https://nebuchadnezzar-megolm.github.io/static/paper.pdf",
      filename: "matrix-megolm-2023.pdf",
      year: 2023,
    },
    {
      id: "acad-mtproto-2021",
      firm: "Royal Holloway / ETH Zurich",
      target: "Telegram MTProto 2.0",
      url: "https://mtpsym.github.io/paper.pdf",
      filename: "mtproto-2021.pdf",
      year: 2021,
    },
  ];
}

// ─────────────────────────────────────────────────────────────
// Main: discover everything
// ─────────────────────────────────────────────────────────────

export async function discoverAll(existingIds?: Set<string>): Promise<DiscoveredReport[]> {
  const known = existingIds || new Set<string>();
  const all: DiscoveredReport[] = [];
  const dedup = new Set<string>();

  const add = (reports: DiscoveredReport[]) => {
    for (const r of reports) {
      if (!known.has(r.id) && !dedup.has(r.url)) {
        dedup.add(r.url);
        all.push(r);
      }
    }
  };

  console.log("\n  [1/4] Crawling master repo (83 audit firms)...");
  const master = await crawlMasterRepo();
  add(master);
  console.log(`    → ${master.length} reports from master repo`);

  console.log("  [2/4] Crawling Trail of Bits (official repo)...");
  const tob = await crawlTrailOfBits();
  add(tob);
  console.log(`    → ${tob.length} reports from Trail of Bits`);

  console.log("  [3/4] Crawling Cure53 (website)...");
  const cure53 = await crawlCure53();
  add(cure53);
  console.log(`    → ${cure53.length} reports from Cure53`);

  console.log("  [4/4] Adding known academic papers...");
  add(getKnownReports());

  console.log(`\n  Total discovered: ${all.length} unique reports\n`);
  return all;
}
