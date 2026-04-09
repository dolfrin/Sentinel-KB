// Fetches audit reports from known sources and stores locally

import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import * as http from "http";
import { auditSources, AuditSource } from "./sources.js";

const REPORTS_DIR = path.join(process.env.HOME || "~", ".messenger-audit", "reports");

/** Ensure reports directory exists */
function ensureDir(dir: string) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/** Download a URL to a file, following redirects */
function download(url: string, dest: string): Promise<void> {
  return new Promise((resolve, reject) => {
    ensureDir(path.dirname(dest));

    const request = (currentUrl: string, redirectCount: number) => {
      if (redirectCount > 10) {
        reject(new Error("Too many redirects"));
        return;
      }

      const client = currentUrl.startsWith("https") ? https : http;

      client.get(currentUrl, { headers: { "User-Agent": "messenger-audit/0.1" } }, (response) => {
        // Follow redirects
        if (response.statusCode && response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          response.resume(); // drain
          const location = response.headers.location;
          const fullUrl = location.startsWith("http") ? location : new URL(location, currentUrl).href;
          request(fullUrl, redirectCount + 1);
          return;
        }

        if (response.statusCode !== 200) {
          response.resume();
          reject(new Error(`HTTP ${response.statusCode}`));
          return;
        }

        // Check content-type — reject HTML when expecting PDF
        const ct = response.headers["content-type"] || "";
        if (ct.includes("text/html")) {
          response.resume();
          reject(new Error("Got HTML instead of PDF (likely Cloudflare/login wall)"));
          return;
        }

        const file = fs.createWriteStream(dest);
        response.pipe(file);
        file.on("finish", () => {
          file.close();
          // Validate non-empty
          const stats = fs.statSync(dest);
          if (stats.size === 0) {
            fs.unlinkSync(dest);
            reject(new Error("Downloaded file is empty"));
          } else {
            resolve();
          }
        });
      }).on("error", (err) => {
        if (fs.existsSync(dest)) fs.unlinkSync(dest);
        reject(err);
      });
    };

    request(url, 0);
  });
}

/** Get local path for a report */
export function getReportPath(source: AuditSource): string {
  const ext = source.type === "pdf" ? ".pdf" : ".html";
  return path.join(REPORTS_DIR, `${source.id}${ext}`);
}

/** Check if a report is already downloaded (and not empty/corrupt) */
export function isDownloaded(source: AuditSource): boolean {
  const p = getReportPath(source);
  if (!fs.existsSync(p)) return false;
  const stats = fs.statSync(p);
  if (stats.size === 0) {
    fs.unlinkSync(p); // remove empty files
    return false;
  }
  // Check if it's actually a PDF (not HTML error page)
  if (source.type === "pdf") {
    const fd = fs.openSync(p, "r");
    const buf = Buffer.alloc(5);
    fs.readSync(fd, buf, 0, 5, 0);
    fs.closeSync(fd);
    if (buf.toString() !== "%PDF-") {
      fs.unlinkSync(p); // remove non-PDF files
      return false;
    }
  }
  return true;
}

/** Fetch a single report */
export async function fetchReport(source: AuditSource): Promise<{ success: boolean; path: string; error?: string }> {
  const dest = getReportPath(source);

  if (isDownloaded(source)) {
    return { success: true, path: dest };
  }

  try {
    await download(source.url, dest);
    return { success: true, path: dest };
  } catch (err: any) {
    return { success: false, path: dest, error: err.message };
  }
}

/** Fetch all reports, returns summary */
export async function fetchAllReports(): Promise<{
  total: number;
  downloaded: number;
  skipped: number;
  failed: { id: string; error: string }[];
}> {
  const results = { total: auditSources.length, downloaded: 0, skipped: 0, failed: [] as { id: string; error: string }[] };

  for (const source of auditSources) {
    if (isDownloaded(source)) {
      results.skipped++;
      continue;
    }

    console.log(`  Downloading: ${source.id} (${source.firm} → ${source.target})...`);
    const result = await fetchReport(source);

    if (result.success) {
      results.downloaded++;
      console.log(`  ✓ ${source.id}`);
    } else {
      results.failed.push({ id: source.id, error: result.error || "Unknown error" });
      console.log(`  ✗ ${source.id}: ${result.error}`);
    }
  }

  return results;
}

/** List all downloaded reports */
export function listDownloaded(): { source: AuditSource; path: string; sizeMB: number }[] {
  return auditSources
    .filter((s) => isDownloaded(s))
    .map((s) => {
      const p = getReportPath(s);
      const stats = fs.statSync(p);
      return { source: s, path: p, sizeMB: Math.round((stats.size / 1024 / 1024) * 100) / 100 };
    });
}

export { REPORTS_DIR };
