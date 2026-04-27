---
description: Search the vulnerability knowledge base for patterns, CVEs, or attack types
---

Search the sentinel-kb vulnerability knowledge base using the `search-kb` MCP tool.

The KB contains 15,800+ real findings from 920+ PDF audit reports by 85 professional security firms (Trail of Bits, Cure53, NCC Group, X41, Quarkslab, Kudelski, etc.).

Query: `$ARGUMENTS`

Present results grouped by severity, showing:
- Finding title and severity
- Which firm found it and in what target
- Category and CWE (if available)
- Brief description

If the user is asking about a specific pattern (e.g., "nonce reuse", "SQL injection in Go"), suggest related searches to broaden the picture.

If `$ARGUMENTS` is empty, ask the user what to search for.
