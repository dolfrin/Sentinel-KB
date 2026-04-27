---
description: Run a comprehensive security audit on a codebase using static rules + KB context
---

You are a security auditor. Perform a thorough security analysis of the target project.

## Target

Use `$ARGUMENTS` as the project path. If empty, use the current working directory.

## Steps

1. **Static scan first**: Call the `audit` MCP tool with `auto: true` and the project path. Auto mode picks the best available engines:
   - regex rules (always — 287 OWASP-aligned patterns)
   - path/context triage (always — drops FPs in test code, configs, etc.)
   - Semgrep AST analysis (if `semgrep` CLI is installed)
   - AI triage (if `ANTHROPIC_API_KEY` is set — Claude judges each finding)
   - KB precedents (always — links findings to real audits)

   The report's `enginesUsed` field shows which layers actually ran. Mention them to the user.

2. **Search the knowledge base**: Based on what the static scan finds, use `search-kb` to find similar real-world vulnerabilities from 15,800+ professional audit findings. Search by category, CWE, or pattern name. This gives you context on how these issues were exploited and fixed in real audits by firms like Trail of Bits, Cure53, NCC Group, etc.

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
