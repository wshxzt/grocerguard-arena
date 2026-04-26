---
name: fetch_service_logs
description: Fetches live application logs from a deployed Cloud Run service.
---

# Skill: Fetch Service Logs

## Purpose
This skill allows you to examine the live runtime logs of a deployed service (like `grocerguard` or `leaderboard`) to identify anomalies, ongoing attacks, or exceptions that are not visible in the source code.

## Instructions
1. Use the underlying `execute_fetch_service_logs` tool to pull the logs.
2. Provide the name of the service (e.g., `"grocerguard"`).
3. Analyze the returned logs for suspicious activity such as:
   - Frequent 500 Internal Server Errors.
   - Suspicious payloads in HTTP requests (e.g., `<script>`, `' OR 1=1`).
   - Unhandled exceptions or traceback dumps.
4. If you find evidence of an attack, use this information to determine which file in the codebase is vulnerable.
