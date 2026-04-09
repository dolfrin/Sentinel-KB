/**
 * Freemium gate module.
 *
 * Accepts an array of findings and returns a GatedResult that exposes the
 * highest-severity findings up to `freeLimit` while stripping sensitive
 * details from the remainder.
 */

export interface GateConfig {
  freeLimit?: number;
  upgradeUrl?: string;
}

export interface GatedResult<T> {
  visible: T[];
  gated: { severity: string; category: string; title: string }[];
  isGated: boolean;
  gateMessage?: string;
  totalCount: number;
}

// Severity rank: lower number = higher priority
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityRank(s: string): number {
  return SEVERITY_ORDER[s.toLowerCase()] ?? 5;
}

/**
 * Gate findings based on the free tier limit.
 *
 * - Sorts all findings by severity (critical → info) before splitting.
 * - The first `freeLimit` (sorted) findings are returned as `visible`.
 * - The remainder are stripped to { severity, category, title } and returned
 *   as `gated`.
 * - A human-readable `gateMessage` is included when gating is active.
 */
export function gateFindings<T extends { severity: string; category: string; title: string }>(
  findings: T[],
  config?: GateConfig
): GatedResult<T> {
  const freeLimit = config?.freeLimit ?? 5;
  const upgradeUrl = config?.upgradeUrl ?? "https://sentinel-kb.dev/upgrade";
  const totalCount = findings.length;

  // Sort a copy by severity so the most important findings are always visible.
  const sorted = [...findings].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity)
  );

  if (totalCount <= freeLimit) {
    return {
      visible: sorted,
      gated: [],
      isGated: false,
      totalCount,
    };
  }

  const visible = sorted.slice(0, freeLimit);
  const gatedRaw = sorted.slice(freeLimit);

  const gated = gatedRaw.map(({ severity, category, title }) => ({
    severity,
    category,
    title,
  }));

  const gateMessage = `Found ${gated.length} more vulnerabilities. Upgrade for full details: ${upgradeUrl}`;

  return {
    visible,
    gated,
    isGated: true,
    gateMessage,
    totalCount,
  };
}
