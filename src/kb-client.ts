// Remote KB client — drop-in replacement for local db.ts methods when KB_API_URL is set
// Reads KB_API_URL and KB_API_KEY from env vars. Uses in-memory cache with TTL.

import type { KBStats } from "./db.js";
import type { ExtractedFinding } from "./extractor.js";

const KB_API_URL = (process.env.KB_API_URL || "").replace(/\/+$/, "");
const KB_API_KEY = process.env.KB_API_KEY || "";

// ─── Cache ───────────────────────────────────────────────────

interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

const STATS_TTL_MS = 5 * 60 * 1000;   // 5 minutes
const SEARCH_TTL_MS = 1 * 60 * 1000;  // 1 minute

const MAX_CACHE_SIZE = 200;
const cache = new Map<string, CacheEntry<unknown>>();

function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.data as T;
}

function setCache<T>(key: string, data: T, ttlMs: number): T {
  // Evict oldest entries if cache is full
  if (cache.size >= MAX_CACHE_SIZE) {
    const firstKey = cache.keys().next().value;
    if (firstKey !== undefined) cache.delete(firstKey);
  }
  cache.set(key, { data, expiresAt: Date.now() + ttlMs });
  return data;
}

// ─── HTTP fetch helper ───────────────────────────────────────

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(path, KB_API_URL);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v) url.searchParams.set(k, v);
    }
  }

  const headers: Record<string, string> = {
    "Accept": "application/json",
  };
  if (KB_API_KEY) {
    headers["Authorization"] = `Bearer ${KB_API_KEY}`;
  }

  const res = await fetch(url.toString(), { headers });

  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`KB API ${res.status}: ${body || res.statusText}`);
  }

  return res.json() as Promise<T>;
}

// ─── Public API (mirrors db.ts methods) ──────────────────────

/** Returns true when KB_API_URL is configured, meaning we should use remote KB */
export function isRemoteKB(): boolean {
  return KB_API_URL.length > 0;
}

/** Fetch KB stats — cached for 5 minutes */
export async function getStats(): Promise<KBStats> {
  const cacheKey = "stats";
  const cached = getCached<KBStats>(cacheKey);
  if (cached) return cached;

  const data = await apiFetch<KBStats>("/api/stats");
  return setCache(cacheKey, data, STATS_TTL_MS);
}

/** Full-text search findings, optionally filtered by category — cached for 1 minute */
export async function searchFindings(
  query: string,
  options?: { category?: string; limit?: number }
): Promise<ExtractedFinding[]> {
  const params: Record<string, string> = { q: query };
  if (options?.category) params.category = options.category;
  if (options?.limit) params.limit = String(options.limit);

  const cacheKey = `search:${JSON.stringify(params)}`;
  const cached = getCached<ExtractedFinding[]>(cacheKey);
  if (cached) return cached;

  const data = await apiFetch<ExtractedFinding[]>("/api/search", params);
  return setCache(cacheKey, data, SEARCH_TTL_MS);
}

/** Get relevant findings by categories — cached for 1 minute */
export async function getRelevantFindingsByCategories(
  categories: string[],
  limit?: number
): Promise<ExtractedFinding[]> {
  const params: Record<string, string> = {};
  if (categories.length > 0) params.categories = categories.join(",");
  if (limit) params.limit = String(limit);

  const cacheKey = `findings:${JSON.stringify(params)}`;
  const cached = getCached<ExtractedFinding[]>(cacheKey);
  if (cached) return cached;

  const data = await apiFetch<ExtractedFinding[]>("/api/findings", params);
  return setCache(cacheKey, data, SEARCH_TTL_MS);
}

/** Health check — not cached */
export async function healthCheck(): Promise<{ ok: boolean; findings: number; reports: number }> {
  return apiFetch<{ ok: boolean; findings: number; reports: number }>("/api/health");
}
