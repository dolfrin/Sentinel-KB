// Lightweight HTTP API server for the security audit knowledge base
// Usage: KB_API_KEY=secret PORT=3737 npx tsx src/kb-api.ts

import * as http from "http";
import { getDB, type KBStats, type FindingRow } from "./db.js";
import type { ExtractedFinding } from "./extractor.js";

const PORT = parseInt(process.env.PORT || "3737", 10);
const API_KEY = process.env.KB_API_KEY || "";

// ─── Helpers ─────────────────────────────────────────────────

function parseURL(req: http.IncomingMessage): URL {
  return new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
}

function json(res: http.ServerResponse, data: unknown, status: number = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
  });
  res.end(body);
}

function error(res: http.ServerResponse, message: string, status: number) {
  json(res, { error: message }, status);
}

function checkAuth(req: http.IncomingMessage, url: URL): boolean {
  if (!API_KEY) return true; // no key configured = open access

  // Check Bearer token
  const authHeader = req.headers.authorization || "";
  if (authHeader.startsWith("Bearer ") && authHeader.slice(7) === API_KEY) {
    return true;
  }

  // Check query param
  if (url.searchParams.get("apiKey") === API_KEY) {
    return true;
  }

  return false;
}

// ─── Route handlers ──────────────────────────────────────────

function handleStats(_req: http.IncomingMessage, _url: URL): { data: KBStats } {
  const db = getDB();
  return { data: db.getStats() };
}

function handleSearch(_req: http.IncomingMessage, url: URL): { data: ExtractedFinding[] } {
  const db = getDB();
  const q = url.searchParams.get("q") || "";
  const category = url.searchParams.get("category") || "";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "25", 10), 500);

  if (!q) {
    return { data: [] };
  }

  let rows: FindingRow[];
  if (category) {
    rows = db.searchFindingsByCategory(q, category.split(",").map(c => c.trim()), limit);
  } else {
    rows = db.searchFindings(q, limit);
  }

  return { data: db.toExtractedFindings(rows) };
}

function handleFindings(_req: http.IncomingMessage, url: URL): { data: ExtractedFinding[] } {
  const db = getDB();
  const categoriesParam = url.searchParams.get("categories") || "";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "20", 10), 500);
  const categories = categoriesParam ? categoriesParam.split(",").map(c => c.trim()) : [];

  const rows = db.getRelevantFindingsByCategories(categories, limit);
  return { data: db.toExtractedFindings(rows) };
}

function handleHealth(_req: http.IncomingMessage, _url: URL): { data: { ok: true; findings: number; reports: number } } {
  const db = getDB();
  const stats = db.getStats();
  return {
    data: {
      ok: true as const,
      findings: stats.total_findings,
      reports: stats.total_reports,
    },
  };
}

// ─── Router ──────────────────────────────────────────────────

const routes: Record<string, (req: http.IncomingMessage, url: URL) => { data: unknown }> = {
  "/api/stats": handleStats,
  "/api/search": handleSearch,
  "/api/findings": handleFindings,
  "/api/health": handleHealth,
};

// ─── Server ──────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const start = Date.now();
  const url = parseURL(req);
  const pathname = url.pathname;

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
    });
    res.end();
    return;
  }

  // Auth check — all endpoints require API key
  if (!checkAuth(req, url)) {
    error(res, "Unauthorized", 401);
    const duration = Date.now() - start;
    console.log(`${req.method} ${pathname} 401 ${duration}ms`);
    return;
  }

  // Route dispatch
  const handler = routes[pathname];
  if (!handler) {
    error(res, "Not found", 404);
    const duration = Date.now() - start;
    console.log(`${req.method} ${pathname} 404 ${duration}ms`);
    return;
  }

  try {
    const result = handler(req, url);
    json(res, result.data);
    const duration = Date.now() - start;
    console.log(`${req.method} ${pathname} 200 ${duration}ms`);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Internal server error";
    error(res, message, 500);
    const duration = Date.now() - start;
    console.log(`${req.method} ${pathname} 500 ${duration}ms — ${message}`);
  }
});

server.listen(PORT, () => {
  console.log(`KB API server listening on http://localhost:${PORT}`);
  console.log(`Auth: ${API_KEY ? "API key required" : "open (no KB_API_KEY set)"}`);
  console.log(`Endpoints:`);
  console.log(`  GET /api/health`);
  console.log(`  GET /api/stats`);
  console.log(`  GET /api/search?q=...&category=...&limit=25`);
  console.log(`  GET /api/findings?categories=cat1,cat2&limit=20`);
});
