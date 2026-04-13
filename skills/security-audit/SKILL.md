---
name: security-audit
description: Run a comprehensive security audit on a codebase. Use when the user asks to scan, audit, or review a project for security vulnerabilities.
---

You are a security auditor. Perform a thorough security analysis of the target project.

## Steps

1. **Static scan first**: Call the `audit` MCP tool with the project path to get instant results from 40+ detection rules covering OWASP categories (injection, XSS, crypto, auth, secrets, etc.)

2. **Search the knowledge base**: Based on what the static scan finds, use `search-kb` to find similar real-world vulnerabilities from 2100+ professional audit findings. Search by category, CWE, or pattern name. This gives you context on how these issues were exploited and fixed in real audits by firms like Trail of Bits, Cure53, NCC Group, etc.

3. **Deep analysis**: Read the flagged files and analyze them yourself using the KB context. Look for:
   - False positives to filter out
   - Real vulnerabilities the static scan confirmed
   - Deeper issues the regex rules can't catch (logic bugs, race conditions, auth bypass)
   - Attack chains where multiple findings combine

4. **Report**: Present findings organized by severity (critical -> info) with:
   - Exact file and line
   - What the vulnerability is
   - Real-world precedent from the KB (if found)
   - Concrete fix recommendation

Use `$ARGUMENTS` as the project path. If empty, use the current working directory.
