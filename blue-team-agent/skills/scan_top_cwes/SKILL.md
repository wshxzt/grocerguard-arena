---
name: scan_top_cwes
description: Perform a localized heuristic static analysis on a codebase for the Top 3 most dangerous CWEs.
---

# Skill: Scan Top CWEs

## Purpose
When searching for vulnerabilities, it is often more efficient to do a quick heuristic scan for common patterns rather than reading every file manually. This skill runs a fast static analysis across the target directory to identify potential XSS, SQLi, and Command Injection flaws.

## Instructions
1. Invoke the underlying `execute_scan_top_cwes` tool.
2. Provide the directory to scan. If you want to scan the main codebase, provide `"."`. If you want to scan a downloaded container filesystem, provide the path to that extracted directory (e.g., `"/tmp/inspections/grocerguard"`).
3. The scanner uses regular expressions to look for:
   - **CWE-89 (SQL Injection)**: Unsafe string formatting inside `.execute()` blocks.
   - **CWE-79 (XSS)**: Use of the `|safe` filter in Jinja templates which bypasses HTML auto-escaping.
   - **CWE-78 (OS Command Injection)**: Use of `os.system` or `subprocess.Popen(..., shell=True)`.
4. Review the results returned by the scanner. Note that these are heuristics and may return false positives, so you must manually verify the findings before attempting a patch.
