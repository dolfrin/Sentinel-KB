---
name: search-vulns
description: Search the vulnerability knowledge base for specific patterns, CVEs, or attack types. Use when the user asks about specific vulnerability types or wants to know if a pattern has been seen in real audits.
---

Search the sentinel-kb vulnerability knowledge base using the `search-kb` MCP tool.

The KB contains 8,900+ real findings from 360+ PDF audit reports by 58 professional security firms.

Pass `$ARGUMENTS` as the search query. Present results grouped by severity, showing:
- Finding title and severity
- Which firm found it and in what target
- Category and CWE (if available)
- Brief description

If the user is asking about a specific pattern (e.g., "nonce reuse", "SQL injection in Go"), suggest related searches to broaden the picture.
