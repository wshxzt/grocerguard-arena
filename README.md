# GrocerGuard Arena

A live security testing arena where two LLM agents — a Red Team and a Blue Team — take turns attacking and patching a deliberately-vulnerable grocery web app. Every attack, defense, and finding is recorded and rendered on a public leaderboard.

The four services run side-by-side on Cloud Run, share a single Spanner database, and watch each other's work in near-real-time.

## Components

| Service | What it does | Stack |
|---|---|---|
| `grocerguard-app/` | Target Flask app — the thing being attacked. Holds the deliberate vulnerabilities. | Flask, Spanner |
| `red-team-agent/` | Picks a CWE, injects a vulnerability into the target, deploys it, then exploits it over HTTP. | Anthropic Claude (`claude-opus-4-7` for runs, `claude-sonnet-4-6` for the chat assistant) |
| `blue-team-agent/` | Inspects the deployed target, hunts for vulnerabilities (planned + unplanned), patches them, and redeploys. | Google ADK + Gemini 2.5 Flash |
| `leaderboard/` | Public dashboard — agent runs, exploits, defenses, CWE registry, feedback form. | Flask, Spanner |

## How a round plays out

Both agents are human-triggered from their respective consoles — there's no scheduler or auto-wakeup.

1. **Red team** is launched from the Red Team Console (chat box or "Run an attack" button) for a chosen CWE — say CWE-352 / CSRF.
2. The agent reads the live `grocerguard` codebase, edits a route to remove CSRF protection, redeploys, then sends an HTTP request that proves the exploit works. Result is logged.
3. **Blue team** is launched from the Blue Team Console. It syncs the deployed source and walks through every applicable CWE plan. For each one it does a code search, a 4-case decision-matrix analysis, and a forensic log scan. Any CWE it confirms gets patched and redeployed.
4. Both teams' findings stream onto the leaderboard.

The two services preserve each other's changes by syncing from the live container image (via `crane`) before each run, so the red team builds on top of the blue team's most recent patches and vice versa — instead of constantly reverting each other off a stale git checkout.

## Screenshots

### Red Team agent — chat & run bubble

![Red Team agent bubble](docs/red-team-bubble.png)

Drives the red team from a chat assistant. The bubble in the corner streams thinking summaries, tool calls, and final findings while a run is in flight.

### Blue Team agent — pipeline bubble

![Blue Team agent bubble](docs/blue-team-bubble.png)

The blue team's bubble shows the multi-CWE pipeline: which CWEs are queued, currently being analyzed, confirmed, ruled out, or patched. It also surfaces the Refine sub-agent's questions when the plan needs clarification.

## Leaderboard

The leaderboard is the public scoreboard for everything happening in the arena. Pages:

- **Home (`/`)** — Scoreboard at the top (red vs blue tallies), then the Red Team Attack Log and Blue Team Fix History grouped per agent run, so you can see exactly which CWEs each run touched and what came out of it.
- **Confirmed Exploits (`/exploits`)** — Every successful red-team exploit with payload, target URL, evidence snippet, and the run id that produced it.
- **Defenses (`/defenses`)** — Per-CWE patches the blue team has shipped, dedup'd to one row per CWE per run with pass/fail status.
- **Agent Runs (`/agent-runs`, `/agent-runs/<run_id>`)** — Full per-run history for both teams: instructions, status, step-by-step trace (thinking summaries, tool calls, deploy outcomes), and any pending question the agent paused on.
- **CWE Registry (`/cwes`, `/cwes/<cwe_id>`)** — The MITRE Top 25 plus any extras the red team auto-pulled from MITRE on demand. Each detail page shows the plan_notes, code_patterns, and live counts of attacks/defenses that have hit it.
- **Feedback (`/feedback`)** — Public form for bug reports and ideas (optional name/email, required body). Submissions land in Spanner and are reviewed at `/feedback/all`.
- **Deploy Log (`/deploys`)** — Every red-team deploy attempt with success/failure and the truncated stderr, so failed pushes are easy to triage.

All timestamps render in PST. The header carries quick links to GrocerGuard App, Leaderboard, CWE Registry, and Feedback.

## Layout

```
grocerguard-arena/
├── grocerguard-app/      # target Flask app
├── red-team-agent/       # Anthropic Claude attacker
├── blue-team-agent/      # ADK + Gemini defender
├── leaderboard/          # Flask dashboard
└── docs/                 # screenshots, etc.
```

Each service has its own `Dockerfile`. All four share one Spanner instance.

## Status

Active development. The arena runs continuously; new CWEs and plan refinements land regularly.
