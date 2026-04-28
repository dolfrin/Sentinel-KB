<p align="center">
  <h1 align="center">Sentinel-KB</h1>
  <p align="center">
    Security vulnerability scanner backed by real audit data from professional firms.
  </p>
</p>

<p align="center">
  <a href="https://github.com/dolfrin/Sentinel-KB/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="https://github.com/dolfrin/Sentinel-KB/releases"><img src="https://img.shields.io/badge/version-0.1.0-brightgreen.svg" alt="Version"></a>
  <a href="https://github.com/dolfrin/Sentinel-KB/actions"><img src="https://img.shields.io/badge/tests-passing-brightgreen.svg" alt="Tests"></a>
  <a href="https://github.com/dolfrin/Sentinel-KB"><img src="https://img.shields.io/badge/rules-287-orange.svg" alt="Rules"></a>
</p>

---

Sentinel-KB scans codebases for security vulnerabilities using **287 static analysis rules** and a **knowledge base of 15,800+ real findings** extracted from 920+ audit reports published by 85 professional security firms -- Trail of Bits, Cure53, NCC Group, QuarksLab, and more.

Unlike synthetic rule sets, every pattern in the knowledge base traces back to a vulnerability that was found, reported, and fixed in a real-world audit. When Sentinel-KB flags something in your code, it can tell you which firm found the same class of bug, in what context, and how it was remediated.

Works as a **Claude Code plugin**, a **CLI tool**, and an **MCP server**.

### Pipeline

Sentinel-KB chains four engines, each one cutting false positives further:

1. **Regex** (always) -- 287 OWASP-aligned patterns, instant, offline
2. **Triage** (always) -- drops findings on config files (`google-services.json`, lockfiles, `*.example`), downgrades severity in test paths and inline `#[cfg(test)]` blocks, applies per-rule context checks (Axum extractors, Android `LAUNCHER` activities, `withSessionLock` wrappers, etc.)
3. **Semgrep** (optional) -- AST-based analysis when `semgrep` CLI is installed
4. **AI triage** (optional) -- Claude Sonnet judges each finding against the knowledge base when `ANTHROPIC_API_KEY` is set

Auto mode picks engines based on what's available -- no setup, no flags.

Marketplace note: this repository can be installed locally as a Claude Code plugin. If an official marketplace listing is published later, installation can use the marketplace flow instead.

## Quick Start

### Claude Code Plugin (recommended)

```bash
# Clone the repo and install the plugin locally
git clone https://github.com/dolfrin/Sentinel-KB.git
cd Sentinel-KB
claude plugin add .

# Run a security audit on any project
claude> /sentinel-kb:audit /path/to/project

# Search the knowledge base
claude> /sentinel-kb:search "nonce reuse AES-GCM"

# Scan a single file
claude> /sentinel-kb:scan-file src/auth/login.ts

# Show KB statistics
claude> /sentinel-kb:stats
```

### CLI

```bash
git clone https://github.com/dolfrin/Sentinel-KB.git
cd Sentinel-KB
npm install

# Auto mode -- picks the best engines available (recommended)
npx tsx src/cli.ts scan /path/to/project --auto

# Plain regex scan (fastest)
npx tsx src/cli.ts scan /path/to/project

# Search the knowledge base
npx tsx src/cli.ts search "SQL injection parameterized"

# View KB statistics
npx tsx src/cli.ts stats

# SARIF output for GitHub Code Scanning
npx tsx src/cli.ts scan /path/to/project --auto --sarif > findings.sarif
```

## What Makes It Different

| Feature | Sentinel-KB | Typical linters |
|---------|------------|-----------------|
| **Rule source** | Extracted from real audit reports | Written by tool authors |
| **Coverage** | 33 categories, 287 rules | Usually 5-10 categories |
| **Languages** | TypeScript, Java, Kotlin, Rust, Go, PHP, Ruby, Python, Solidity, Swift, C/C++ | Usually 1-3 |
| **AI analysis** | Claude analyzes code with KB context | Pattern matching only |
| **Knowledge base** | 15,800+ findings from 85 firms | None |
| **False positive rate** | Tuned against real codebases | Often high |

## Static Scan Categories

The 287 rules cover 33 security categories:

| Category | Category | Category |
|----------|----------|----------|
| Injection | XSS | SSRF/CSRF |
| Authentication | Secrets | Cryptography |
| Session & Cookie Security | API Security | Database Security |
| E2E Encryption | WebRTC/P2P | Messenger |
| Android | iOS Security | Memory Safety |
| Concurrency | Deserialization | File & Path Security |
| Network Security | Configuration Security | Error Handling & Logging |
| Cloud & Infrastructure | Privacy & Data Protection | Supply Chain & Dependencies |
| Smart Contracts | Go Security | PHP Security |
| Ruby Security | Python Security | CI/CD Security |
| Infrastructure as Code | Input Validation | Backend |

Every rule includes CWE identifiers, severity ratings, and targeted file patterns.

## Slash Commands

When installed as a Claude Code plugin, Sentinel-KB exposes four slash commands:

| Command | Description |
|---------|-------------|
| `/sentinel-kb:audit [path]` | Comprehensive audit in auto mode -- runs all available engines (regex + triage + Semgrep + AI triage + KB precedents), groups findings by category, links each to similar real-world audits |
| `/sentinel-kb:search <query>` | Full-text search the knowledge base by pattern, CWE, category, or attack type |
| `/sentinel-kb:scan-file <path>` | Quick scan of a single file with automatic triage |
| `/sentinel-kb:stats` | Knowledge base statistics: total findings, reports, firms, severity breakdown |

## MCP Tools

The MCP server exposes six tools for programmatic access:

| Tool | Description | Tier |
|------|-------------|------|
| `audit` | Full project scan; pass `auto: true` to enable Semgrep / AI triage when available | Free |
| `ai-audit` | AI-powered scan with KB context, batched | Requires API key |
| `list-rules` | List all 287 detection rules | Free |
| `scan-file` | Scan a single file | Free |
| `kb-stats` | Knowledge base statistics | Free |
| `search-kb` | Full-text search across 15,800+ findings | Free |

## CLI Usage

```bash
# Auto mode -- picks the best engines available (recommended)
npx tsx src/cli.ts scan /path/to/project --auto

# Plain static scan -- instant, offline, no API key needed
npx tsx src/cli.ts scan /path/to/project

# Force-enable Semgrep (needs `pip install semgrep`)
npx tsx src/cli.ts scan /path/to/project --semgrep

# Force-enable AI triage (needs ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-... npx tsx src/cli.ts scan /path/to/project --ai-triage

# Disable triage layer (raw regex output, useful for debugging)
npx tsx src/cli.ts scan /path/to/project --no-triage

# Attach KB precedents (real-world audit findings) to each result
npx tsx src/cli.ts scan /path/to/project --with-kb

# SARIF 2.1.0 output for GitHub Code Scanning
npx tsx src/cli.ts scan /path/to/project --auto --sarif > findings.sarif

# JSON output
npx tsx src/cli.ts scan /path/to/project --json

# Search the knowledge base
npx tsx src/cli.ts search "buffer overflow heap"

# Show knowledge base statistics
npx tsx src/cli.ts stats

# Update the knowledge base
npx tsx src/update.ts
```

### Scan flags

| Flag | Effect |
|------|--------|
| `--auto` | Pick engines automatically based on what's available |
| `--severity <level>` | Threshold: `high` includes `high + critical` |
| `--category <cat>` | Filter to a single category |
| `--include-all-dirs` | Scan dirs that are normally skipped (tests, docs, etc.) |
| `--no-triage` | Disable path/context triage |
| `--semgrep` | Force-enable Semgrep (needs `semgrep` CLI) |
| `--ai-triage` | Force-enable AI judging (needs `ANTHROPIC_API_KEY`) |
| `--min-confidence <n>` | Minimum AI confidence to keep a finding (default 60) |
| `--with-kb` | Attach KB precedents to each finding |
| `--sarif` | Emit SARIF 2.1.0 (GitHub Code Scanning native) |
| `--json` | Emit structured JSON |

## How It Works

```
   +-------------------+
   |    Source code    |
   +---------+---------+
             |
             v
   +-------------------+      +-------------------+
   |   Regex engine    +----->|   Triage layer    |
   |  (287 rules)      |      | path & context    |
   |  always runs      |      | always runs       |
   +-------------------+      +---------+---------+
                                        |
                            optional    |
   +-------------------+      +---------+---------+
   |   Semgrep AST     +----->|                   |
   | if CLI installed  |      |    AI triage      |
   +-------------------+      |  (Claude Sonnet)  |
                              |  if API key set   |
                              +---------+---------+
                                        |
                                        v
   +---------------------------------------------+
   |      Findings + KB precedents               |
   |   Severity, CWE, real-audit attribution     |
   |   Output: text / JSON / SARIF               |
   +---------------------------------------------+
```

**Regex** scans every source file locally for OWASP-aligned vulnerability patterns. Each finding carries severity, CWE, category, and a snippet from real audits.

**Triage** post-processes findings to drop false positives:

- Config files like `google-services.json`, lockfiles, and `*.example` are dropped entirely
- Findings inside test paths or inline `#[cfg(test)]` / `mod tests` blocks are downgraded
- Per-rule context filters check for Axum extractors, `withSessionLock` wrappers, Android `LAUNCHER` activities, generic notification strings, and other shapes regex alone can't see

**Semgrep** (optional) adds AST-based analysis from the Semgrep community ruleset (~2,000 rules). Runs only when `semgrep` is on the PATH; otherwise silently skipped.

**AI triage** (optional) sends each finding -- with 30 lines of code context and the top 3 KB matches by category -- to Claude Sonnet. The model returns a confidence score (0-100), `isReal` verdict, and a one-line reason. Findings below the confidence threshold are filtered; the rest get severity recalibrated based on confidence.

**KB precedents** attach real-world audit findings to each result: `Cure53 -> Silencelabs: hardcoded creds [CWE-798]`. This grounds every finding in actual prior incidents.

**Output formats** include human-readable text (default), structured JSON, and SARIF 2.1.0 for GitHub Code Scanning.

## Knowledge Base

The knowledge base is built by crawling and extracting findings from publicly available security audit reports:

- **15,800+ findings** from **920+ PDF reports** by **85 audit firms**
- Firms include Trail of Bits, Cure53, NCC Group, QuarksLab, Consensys Diligence, OpenZeppelin, and more
- Findings are stored in SQLite with FTS5 full-text search
- Each finding has: severity, category, CWE mapping, description, firm attribution
- Cross-report deduplication identifies the same vulnerability class found independently by multiple firms

### Updating the KB

```bash
# Auto-detect mode: uses AI extraction if ANTHROPIC_API_KEY is set, regex otherwise
npx tsx src/update.ts

# Force regex extraction (free, offline)
npx tsx src/update.ts --regex

# Use a specific model for extraction
npx tsx src/update.ts --ai-model claude-opus-4-20250514

# Show current stats
npx tsx src/update.ts --stats
```

## Self-Hosting

Sentinel-KB can run as a standalone MCP server:

```bash
git clone https://github.com/dolfrin/Sentinel-KB.git
cd Sentinel-KB
npm install
npm run build

# Start the MCP server
npm start
```

Data is stored locally at `~/.security-audit-kb/`:
- `audit.db` -- SQLite database (WAL mode, FTS5)
- `reports/` -- cached PDF audit reports

## Building

```bash
npm install       # install dependencies
npm test          # run test suite
npx tsc           # compile TypeScript
npm run build     # alias for tsc
```

## Contributing

Contributions are welcome. Areas where help is especially useful:

- **New detection rules** -- add rules to `src/rules.ts` with tests
- **Audit report sources** -- add URLs to `src/sources.ts`
- **False positive tuning** -- add filters to `src/triage.ts` and a regression test in `src/__tests__/triage.test.ts`
- **Per-rule context checks** -- extend `RULE_FILTERS` in `src/triage.ts` to teach the scanner about idiomatic patterns it currently flags by mistake
- **Output formats** -- additional report formats can live alongside `formatText` / `formatJSON` / `formatSARIF` in `src/report.ts`
- **Language support** -- extend file patterns and regex for additional languages

Please open an issue before submitting large changes.

## License

[AGPL-3.0](LICENSE) -- Sentinel-KB is free and open source. If you modify and distribute it, you must share your changes under the same license.
