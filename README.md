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

Sentinel-KB scans codebases for security vulnerabilities using **287 static analysis rules** and a **knowledge base of 2,134 real findings** extracted from 361 audit reports published by 58 professional security firms -- Trail of Bits, Cure53, NCC Group, QuarksLab, and more.

Unlike synthetic rule sets, every pattern in the knowledge base traces back to a vulnerability that was found, reported, and fixed in a real-world audit. When Sentinel-KB flags something in your code, it can tell you which firm found the same class of bug, in what context, and how it was remediated.

Works as a **Claude Code plugin**, a **CLI tool**, and an **MCP server**.

## Quick Start

### Claude Code Plugin (recommended)

```bash
# Install from the Claude Code marketplace
claude plugin add sentinel-kb

# Run a security audit on any project
claude> /security-audit /path/to/project

# Search the knowledge base
claude> /search-vulns "nonce reuse AES-GCM"

# Scan a single file
claude> /scan-file src/auth/login.ts
```

### CLI

```bash
git clone https://github.com/dolfrin/Sentinel-KB.git
cd Sentinel-KB
npm install

# Static scan (free, instant, offline)
npx tsx src/cli.ts scan /path/to/project

# Search the knowledge base
npx tsx src/cli.ts search "SQL injection parameterized"

# View KB statistics
npx tsx src/cli.ts stats
```

## What Makes It Different

| Feature | Sentinel-KB | Typical linters |
|---------|------------|-----------------|
| **Rule source** | Extracted from real audit reports | Written by tool authors |
| **Coverage** | 33 categories, 287 rules | Usually 5-10 categories |
| **Languages** | TypeScript, Java, Kotlin, Rust, Go, PHP, Ruby, Python, Solidity, Swift, C/C++ | Usually 1-3 |
| **AI analysis** | Claude analyzes code with KB context | Pattern matching only |
| **Knowledge base** | 2,134 findings from 58 firms | None |
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

## Skills

When installed as a Claude Code plugin, Sentinel-KB provides four skills:

| Skill | Description |
|-------|-------------|
| `/security-audit` | Full security audit -- runs static scan, searches KB for context, then Claude analyzes flagged code for real vulnerabilities and false positives |
| `/search-vulns` | Search the knowledge base by pattern, CWE, category, or attack type. Returns real findings from professional audits |
| `/scan-file` | Quick scan of a single file with automatic triage of results |
| `/kb-stats` | Knowledge base statistics: total findings, reports, firms, severity breakdown |

## MCP Tools

The MCP server exposes six tools for programmatic access:

| Tool | Description | Tier |
|------|-------------|------|
| `audit` | Full static scan of a project directory | Free |
| `ai-audit` | AI-powered scan with KB context | Requires API key |
| `list-rules` | List all 287 detection rules | Free |
| `scan-file` | Scan a single file | Free |
| `kb-stats` | Knowledge base statistics | Free |
| `search-kb` | Full-text search across 2,134 findings | Free |

## CLI Usage

```bash
# Static scan -- instant, offline, no API key needed
npx tsx src/cli.ts scan /path/to/project

# Search the knowledge base
npx tsx src/cli.ts search "buffer overflow heap"

# AI-powered scan (requires ANTHROPIC_API_KEY)
ANTHROPIC_API_KEY=sk-... npx tsx src/cli.ts ai /path/to/project

# Show knowledge base statistics
npx tsx src/cli.ts stats

# Update the knowledge base
npx tsx src/update.ts
```

## How It Works

```
                        +-----------------+
                        |   Claude Code   |
                        |  (or CLI user)  |
                        +--------+--------+
                                 |
                    +------------+------------+
                    |                         |
            +-------+-------+       +--------+--------+
            |  Static Scan  |       |   KB Search /   |
            |  (287 rules)  |       |   AI Analysis   |
            |  offline/free |       |                 |
            +-------+-------+       +--------+--------+
                    |                         |
                    v                         v
            +---------------+       +-----------------+
            | Regex engine  |       | Knowledge Base  |
            | scans source  |       | 2,134 findings  |
            | files locally |       | 361 reports     |
            +-------+-------+       | 58 firms        |
                    |               +--------+--------+
                    |                        |
                    v                        v
            +------------------------------------+
            |     Results with KB context:       |
            |  - Severity, CWE, category         |
            |  - Real-world precedent            |
            |  - Fix recommendations             |
            +------------------------------------+
```

**Static scan** runs locally with zero network calls. Pattern-matched findings include severity, CWE, and a description derived from real audit reports.

**KB-augmented analysis** sends flagged code and relevant KB findings to Claude, which performs deeper analysis -- identifying false positives, finding logic bugs the regex cannot catch, and providing remediation advice grounded in how the same class of vulnerability was fixed in audited projects.

## Knowledge Base

The knowledge base is built by crawling and extracting findings from publicly available security audit reports:

- **2,134 findings** from **361 PDF reports** by **58 audit firms**
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
- **False positive tuning** -- report false positives with the code that triggered them
- **Language support** -- extend file patterns and regex for additional languages

Please open an issue before submitting large changes.

## Support the Project

If Sentinel-KB helped you find a real vulnerability or saved you audit hours, consider supporting the project. Every contribution helps fund server costs, KB expansion, and continued development.

<p align="center">
  <a href="https://github.com/sponsors/dolfrin"><img src="https://img.shields.io/badge/GitHub_Sponsors-Support-ea4aaa?logo=github" alt="GitHub Sponsors"></a>
  <a href="https://buymeacoffee.com/dolfrin"><img src="https://img.shields.io/badge/Buy_Me_a_Coffee-Support-ffdd00?logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>

| Method | Link |
|--------|------|
| GitHub Sponsors | [github.com/sponsors/dolfrin](https://github.com/sponsors/dolfrin) |
| Buy Me a Coffee | [buymeacoffee.com/dolfrin](https://buymeacoffee.com/dolfrin) |
| Bitcoin | `bc1qYOUR_BTC_ADDRESS_HERE` |

## License

[AGPL-3.0](LICENSE) -- Sentinel-KB is free and open source. If you modify and distribute it, you must share your changes under the same license.
