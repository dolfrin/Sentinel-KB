# Sentinel-KB: AI-Powered Security Vulnerability Scanner

AI-powered security scanner that collects real vulnerability patterns from professional audit firms and uses them to scan any codebase. Monetizable product — MCP server, CLI, eventually SaaS.

**Freemium model:** Static scan is free and offline. AI scan (KB context + Claude) is gated behind `ANTHROPIC_API_KEY`.

## What this project does

1. **Crawls** public security audit PDFs from 83+ firms (Trail of Bits, Cure53, NCC Group, QuarksLab, etc.)
2. **Extracts** vulnerability findings using Claude AI (Sonnet/Opus) — understands any report format
3. **Stores** findings in a production SQLite DB with FTS5 search, model versioning, dedup, cost tracking
4. **Scans** any codebase using the KB as context for Claude to find real vulnerabilities

## Architecture

```
src/
├── db.ts            # SQLite DB: schema, FTS5, migrations, queries, model versioning
├── crawler.ts       # Auto-discovers audit reports from GitHub, Cure53, academic papers
├── fetcher.ts       # Downloads PDFs with redirect handling, validation
├── sources.ts       # Static list of known audit report URLs
├── extractor.ts     # Regex-based PDF extraction (fast, offline, free)
├── ai-extractor.ts  # AI extraction via Claude (Sonnet default) — 3-4x more findings
├── update.ts        # Full pipeline: crawl → download → extract → DB
├── ai-scanner.ts    # AI code scanner: KB context + Claude → finds vulnerabilities
├── scanner.ts       # Static regex scanner (fast, offline, free tier)
├── triage.ts        # Path/context FP filtering: config files, test blocks, per-rule checks
├── semgrep.ts       # Optional Semgrep AST engine (no-op if CLI missing)
├── ai-triage.ts     # AI triage: Claude judges each finding with KB context
├── report.ts        # Output formatters: text / JSON / SARIF 2.1.0
├── rules.ts         # Static scan rules (crypto, auth, injection, WebRTC, Android, Rust, etc.)
├── service.ts       # Orchestrator: wires regex → triage → semgrep → ai-triage → report
├── gate.ts          # Freemium gate: checks API key, enforces free/paid tier limits
├── kb-api.ts        # Hosted HTTP API for the knowledge base
├── kb-client.ts     # Remote KB client (used when KB_API_URL is set)
├── index.ts         # MCP server (6 tools)
└── cli.ts           # CLI: scan, ai, stats, search, migrate, update
```

### Scan pipeline

`runStaticScan()` (in `service.ts`) is the entry point used by both the CLI
and the MCP `audit` tool. With `auto: true` it picks engines based on the
environment:

1. **regex** — always (`scanner.ts`, `rules.ts`)
2. **triage** — always (`triage.ts`)
3. **semgrep** — if `semgrep --version` succeeds (`semgrep.ts`)
4. **ai-triage** — if `ANTHROPIC_API_KEY` is set (`ai-triage.ts`)
5. **kb-precedents** — always in auto mode (`report.ts` looks up `db.searchFindingsByCategory`)

`AuditReport.enginesUsed[]` lists which layers actually ran. Output is rendered
by `report.ts` (text / JSON / SARIF) — `scanner.ts` no longer formats reports
directly.

## Database

SQLite at `~/.security-audit-kb/audit.db` (WAL mode, FTS5):
- `reports` — audit report metadata, PDF hash, download status
- `findings` — vulnerabilities with severity, category, CWE, confidence score
- `extractions` — which model extracted what, token usage, cost in USD
- `canonical_findings` — cross-report dedup (same vuln found by multiple firms)
- `model_runs` — per-run cost/performance aggregates
- `findings_fts` — full-text search (porter stemmer, unicode)

Current: ~15,800 findings from 929 PDFs, 85 firms.

## Key commands

```bash
# Update knowledge base (AI mode if ANTHROPIC_API_KEY set, regex otherwise)
ANTHROPIC_API_KEY=... npx tsx src/update.ts

# Force regex mode (free, offline)
npx tsx src/update.ts --regex

# Use specific model
npx tsx src/update.ts --ai-model claude-opus-4-20250514

# Show DB stats
npx tsx src/update.ts --stats

# Migrate old JSON to SQLite
npx tsx src/update.ts --migrate

# Search KB
npx tsx src/cli.ts search "nonce reuse AES"

# AI scan (requires ANTHROPIC_API_KEY)
npx tsx src/cli.ts ai /path/to/project --model sonnet

# Static scan (free, no API needed)
npx tsx src/cli.ts scan /path/to/project

# Auto mode — picks regex + triage + semgrep + ai-triage + kb-precedents based on availability
npx tsx src/cli.ts scan /path/to/project --auto

# SARIF output for GitHub Code Scanning
npx tsx src/cli.ts scan /path/to/project --auto --sarif > findings.sarif
```

## MCP Tools (6)

- `audit` — full static regex scan (free tier)
- `ai-audit` — AI-powered scan with KB context (requires API key)
- `list-rules` — show all static scan rules
- `scan-file` — scan single file
- `kb-stats` — knowledge base statistics
- `search-kb` — full-text search the KB

## Environment

- `ANTHROPIC_API_KEY` — required for AI extraction and AI scanning (free tier uses static scan only)
- Daily cron at 3AM auto-updates the KB
- PDF cache: `~/.security-audit-kb/reports/`
- DB: `~/.security-audit-kb/audit.db`
- JSON export (backwards compat): `~/.security-audit-kb/knowledge-base.json`

## Model versioning

Each model (sonnet/opus/haiku) gets its own extraction records in DB. Switching models triggers re-extraction of all PDFs — old results preserved for comparison. Cost tracked per extraction and per run.

## Build

```bash
npm install
npm test          # run test suite
npx tsc           # compile
npx tsx src/...   # run directly
```

No Android Studio. No Java. Pure TypeScript + SQLite.
