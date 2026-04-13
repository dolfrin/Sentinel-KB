# Privacy Policy

**Sentinel-KB** — Last updated: April 13, 2026

## What Sentinel-KB does

Sentinel-KB is a security vulnerability scanner that can run as a Claude Code plugin, CLI tool, or MCP server. It performs local static analysis, optional hosted knowledge base lookups, and optional AI-powered analysis.

## Data flows

### Static scan (local)
- Runs entirely on your machine
- No code, files, or scan results leave your device
- No data is collected, stored, or transmitted

### Knowledge base API (`kb.quantumwing.io`)
- When you use KB search or KB stats features, the client sends search queries or metadata requests to the hosted knowledge base API
- We log request metadata such as IP address, timestamp, endpoint path, and response time for abuse prevention, reliability, and rate limiting
- We do **not** log search query content
- We do **not** collect, store, or transmit any of your source code
- No cookies, no tracking, no analytics

### AI-powered scan (`ANTHROPIC_API_KEY`)
- If you explicitly run AI scan features, relevant source code excerpts and knowledge base context are sent to Anthropic's API for analysis
- This does not happen during static scan
- Anthropic processes those requests under Anthropic's own terms and privacy practices
- You are responsible for deciding whether the code you send to Anthropic may be processed by a third-party AI provider

## Data storage

- Hosted API access logs are retained for up to 30 days, then deleted
- Local scan results, cached PDFs, and the SQLite database remain on your machine unless you delete them
- No user accounts or registration are required for local scanning

## Third parties

- Anthropic may process source code excerpts only when you use AI scan features
- The hosted knowledge base API runs on infrastructure operated by the project maintainer
- We do not sell your data or use it for advertising

## Contact

For privacy questions: dolfrin@gmail.com

## Changes

We may update this policy. Changes will be posted to this file in the repository.
