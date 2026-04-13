---
name: scan-file
description: Quickly scan a single file for security vulnerabilities. Use when the user points at a specific file rather than a whole project.
---

Scan the specified file using the `scan-file` MCP tool, then analyze the results.

For each finding, read the actual code around the flagged line and determine:
- Is this a true positive or false positive?
- What's the actual risk in context?
- How to fix it?

Use `$ARGUMENTS` as the file path.
