---
name: inspect_deployed_filesystem
description: Downloads and extracts the actual deployed container image for a Cloud Run service to detect rogue files or un-checked dependencies.
---

# Skill: Inspect Deployed Filesystem

## Purpose
Sometimes the Red Team will deploy malicious binaries or vulnerable dependencies directly to the runtime environment, bypassing the main GitHub repository branch. This skill allows you to pull the exact filesystem that is currently running in production.

## Instructions
1. Invoke the underlying `execute_inspect_deployed_filesystem` tool, passing the name of the service (e.g., `"grocerguard"`).
2. Wait for the tool to complete. It will extract the entire running container filesystem into `/tmp/inspections/<service_name>`.
3. Once extracted, you can use your standard `list_files` and `read_file` tools on the `/tmp/inspections/<service_name>` directory to look for anomalies.
4. **Key things to check**:
   - Compare `requirements.txt` against the main branch to see if a vulnerable package was added.
   - Look for unauthorized backdoor scripts or binaries.
   - Check if critical application logic files (`app.py`, etc.) were modified in the deployed container compared to the source code repository.
