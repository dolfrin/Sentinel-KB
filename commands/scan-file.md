---
description: Scan a single file for security vulnerabilities
---

Scan the file at `$ARGUMENTS` using the `scan-file` MCP tool, then analyze the results.

For each finding:
- Read the actual code around the flagged line
- Determine if it's a true positive or false positive
- Explain the actual risk in context
- Suggest how to fix it

If `$ARGUMENTS` is empty, ask the user which file to scan.
