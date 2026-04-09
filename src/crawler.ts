// Auto-discover ALL security audit reports from public sources
// Master source: juliocesarfort/public-pentesting-reports (83 firms)
// Plus: Trail of Bits GitHub, Cure53 website

import * as https from "https";
import * as http from "http";

export interface DiscoveredReport {
  id: string;
  firm: string;
  target: string;
  url: string;
  filename: string;
  year: number;
}

/** Fetch text from URL, following redirects */
function fetchText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const doRequest = (currentUrl: string, depth: number) => {
      if (depth > 10) { reject(new Error("Too many redirects")); return; }
      const c = currentUrl.startsWith("https") ? https : http;
      c.get(currentUrl, { headers: { "User-Agent": "security-audit-kb/0.1", Accept: "application/json" } }, (res) => {
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
// ─────────────────────────────────────────────────────────────

const MASTER_REPO = "juliocesarfort/public-pentesting-reports";
const MASTER_API = `https://api.github.com/repos/${MASTER_REPO}/contents`;

/** Get list of all firm directories in master repo */
async function getMasterFirms(): Promise<{ name: string; path: string }[]> {
  const contents = await fetchJson(MASTER_API);
  return contents
    .filter((item: any) => item.type === "dir")
    .map((item: any) => ({ name: item.name, path: item.path }));
}

/** Get all PDF files from a firm's directory (non-recursive for API rate limits) */
async function getFirmPdfs(firmPath: string): Promise<{ name: string; download_url: string }[]> {
  try {
    const contents = await fetchJson(`${MASTER_API}/${encodeURIComponent(firmPath)}`);
    return contents
      .filter((item: any) => item.type === "file" && item.name.toLowerCase().endsWith(".pdf"))
      .map((item: any) => ({ name: item.name, download_url: item.download_url }));
  } catch (error) {
    console.error(`[sentinel-kb] Failed to crawl firm ${firmPath}: ${error instanceof Error ? error.message : error}`);
    return [];
  }
}

/**
 * Crawl the master repo — all 83 firms.
 * Rate-limited: ~30 API calls.
 */
export async function crawlMasterRepo(progress?: (msg: string) => void): Promise<DiscoveredReport[]> {
  const reports: DiscoveredReport[] = [];
  const log = progress || console.log;

  try {
    const firms = await getMasterFirms();
    log(`  Found ${firms.length} firms in master repo`);

    // Process in batches of 5 to avoid GitHub rate limits
    for (let i = 0; i < firms.length; i += 5) {
      const batch = firms.slice(i, i + 5);
      const results = await Promise.all(
        batch.map(async (firm) => {
          const pdfs = await getFirmPdfs(firm.path);
          return pdfs.map((pdf) => ({
            id: makeId(firm.name, pdf.name),
            firm: firm.name.replace(/([a-z])([A-Z])/g, "$1 $2"), // CamelCase → spaces
            target: filenameToTarget(pdf.name),
            url: pdf.download_url,
            filename: pdf.name,
            year: extractYear(pdf.name),
          }));
        })
      );
      for (const firmReports of results) {
        reports.push(...firmReports);
      }

      // Brief pause between batches to respect rate limits
      if (i + 5 < firms.length) {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
  } catch (err: any) {
    log(`  Failed to crawl master repo: ${err.message}`);
  }

  return reports;
}

// ─────────────────────────────────────────────────────────────
// Source 2: Trail of Bits — official publications repo
// ─────────────────────────────────────────────────────────────

export async function crawlTrailOfBits(): Promise<DiscoveredReport[]> {
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
