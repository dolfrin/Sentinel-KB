# Privacy Policy

**Sentinel-KB** — Last updated: April 13, 2026

## What Sentinel-KB does

Sentinel-KB is a security vulnerability scanner that can run as a Claude Code plugin, CLI tool, or MCP server. It performs local static analysis, optional hosted knowledge base lookups, and AI-assisted analysis depending on how you use it.

## Data flows

### Static scan (local)
- Runs entirely on your machine
- No code, files, or scan results leave your device
- No data is collected, stored, or transmitted

### Claude Code plugin usage
- When you use Sentinel-KB inside Claude Code, Claude Code itself may read and analyze files from your workspace as part of the normal Claude Code product experience
- Sentinel-KB does not require you to provide a separate `ANTHROPIC_API_KEY` for normal Claude Code plugin usage
- The plugin's own hosted features are limited to knowledge base lookups such as KB search and stats

### Knowledge base API (`kb.quantumwing.io`)
- When you use KB search or KB stats features, the client sends search queries or metadata requests to the hosted knowledge base API
- We log request metadata such as IP address, timestamp, endpoint path, and response time for abuse prevention, reliability, and rate limiting
- We do **not** log search query content
- We do **not** collect, store, or transmit any of your source code
- No cookies, no tracking, no analytics

### Standalone AI scan / extraction (`ANTHROPIC_API_KEY`)
- If you run Sentinel-KB outside Claude Code using the standalone CLI or MCP server AI features, and you explicitly enable AI scan or AI extraction, relevant source code excerpts or report text may be sent to Anthropic's API for analysis
- This standalone AI path uses `ANTHROPIC_API_KEY`
- This does not happen during static scan
- Anthropic processes those requests under Anthropic's own terms and privacy practices
- You are responsible for deciding whether the code or report content you send to Anthropic may be processed by a third-party AI provider

## Data storage

- Hosted API access logs are retained for up to 30 days, then deleted
- Local scan results, cached PDFs, and the SQLite database remain on your machine unless you delete them
- No user accounts or registration are required for local scanning

## Third parties

- Claude Code usage is governed by Anthropic's Claude Code product terms and privacy practices
- Anthropic may process source code excerpts or report text when you use Claude Code itself, or when you explicitly enable Sentinel-KB's standalone AI features
- The hosted knowledge base API runs on infrastructure operated by the project maintainer
- We do not sell your data or use it for advertising

## Contact

For privacy questions: dolfrin@gmail.com

## Changes

We may update this policy. Changes will be posted to this file in the repository.
