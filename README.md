# Multi-agent AppSec triage on Claude Managed Agents

A reference demo of **Claude Managed Agents** and the agent lifecycle, using a
realistic AppSec task: triaging SQL injection findings from a static analysis
scanner.

The agent reads a scanner report, opens the flagged source code, traces where
the input comes from, and decides whether each finding is really exploitable.
For each finding it files a **ticket draft** through a tool that our own code
checks before saving. A person reviews every draft. Nothing is filed
automatically.

The same task is built three ways, so you can compare them side by side:

| Script | Built on | Who runs the loop and the tools |
|---|---|---|
| `triage_multi.py` | Claude Managed Agents, multiagent | An orchestrator agent hands each finding to its own subagent, in parallel, then has one verifier agent check all the verdicts. Our code runs the code gate and saves the verdicts. |
| `triage_demo.py` | Claude Managed Agents | Anthropic runs the agent loop and the read-only file tools in a cloud sandbox with no network access. Our code only handles the ticket tool. |
| `triage_loop.py` | Plain Messages API | Our code runs everything: the loop, the file tools, the stop condition, the file access rules, error handling and history. |

## What happens in `triage_multi.py`

Three agents, each with its own model, instructions and tools:

| Agent | Model | Tools | Job |
|---|---|---|---|
| `triage-orchestrator` | Opus 5.5 | `read`, plus our `submit_verdict` tool | Reads the scan, applies the effort rules, delegates, combines the results |
| `finding-triager` | Sonnet 5.5 | `read`, `glob`, `grep` | Triages one finding, or one question about a finding |
| `verifier` | Opus 5.5 | `read`, `grep` | Challenges all the verdicts and their evidence, with a different prompt |

All built-in tools are off except the ones listed. The orchestrator can only
delegate to these two agents: it can't define its own subagents, and dynamic
workflows are off.

The run goes: scan, orchestrator, one subagent per
finding in parallel, verifier, code gate, verdicts. The orchestrator, the
verifier and the code gate run every time; the orchestrator chooses which
findings get a subagent.

1. **Orchestrator and subagents**: the orchestrator applies the effort rules from
   its instructions. Test-code findings get no subagent, typical findings get one,
   and a finding whose input comes from another service gets one per open
   question. The subagents run in parallel.
2. **Verifier**: one verifier gets every verdict and its evidence in a single
   message, including the ones the orchestrator decided itself, and looks for
   what they got wrong.
3. **Code gate**: the orchestrator calls `submit_verdict` for each finding. Our
   code checks that every `file:line` exists and that the quoted code matches
   that line (the whole line, or at least 15 characters of it), and rejects the
   verdict if not, saying what the line really contains. This is a fact check,
   so it's code, not an agent. It checks that the evidence is real, not that the
   verdict is right; that's the verifier's job and the reviewer's.
4. **Verdicts**: each verdict that passes is saved as a draft ticket for a person
   to review. Who decided each finding and whether the verifier agreed are taken
   from the session's own events, not from the orchestrator's word. The
   orchestrator's claim is kept next to them, and the result table flags any
   difference.
5. **Result**: a table of each verdict next to the answer the sample was built
   with, and the cost of each thread. The session has a $5 spend cap
   (`BUDGET_CENTS`).

While it runs, the terminal shows each subagent starting, what the orchestrator
sends it and what it reports back. In the Claude Console, open the session to see
every thread's own steps.

The script also guards against the usual ways a run goes wrong: if our tool
code throws, the error goes back to the agent as a rejection instead of
leaving the session waiting forever; the script stops watching after
`MAX_MINUTES`; and the spend cap ends the session whatever happens.

### When is multi-agent worth it?

With five findings, one agent does this job well: `triage_demo.py` triages the
same scan for a fraction of the cost. The multi-agent version shows the
pattern you'd reach for when one agent isn't enough:

- **Many findings.** Each subagent starts with a clean context, so a long scan
  doesn't crowd one agent's context, and the findings run in parallel.
- **An independent check.** The verifier has a different prompt and its own
  context, so it isn't anchored on the reasoning it's checking.
- **Effort that fits the finding.** Cheap findings get no subagent; hard ones
  get several.

For a real scan with hundreds of findings, you'd also group findings that hit
the same vulnerable line, cap how many subagents run at once, and split the
scan across sessions.

## What happens in `triage_demo.py`

The steps:

1. **Agent**: model, instructions (system prompt) and tools. All built-in
   tools are switched off except `read`, `glob` and `grep`, plus one custom
   tool, `create_ticket_draft`.
2. **Environment**: a cloud sandbox with no network access.
3. **Session**: the agent and environment together, with the sample repo and
   scan report uploaded and mounted read-only.
4. **Events**: we send the task, stream what the agent does, and answer its
   `create_ticket_draft` calls. Our code rejects any draft with an unknown
   finding ID, an invalid verdict or severity, or no `file:line` evidence.
5. **Result**: accepted ticket drafts, plus the session's token usage.

## Setup

You need Python 3.10 or newer and an Anthropic API key with access to Managed
Agents.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                # Windows: copy .env.example .env
```

Then open `.env` and set `ANTHROPIC_API_KEY`. The scripts load `.env` on
start; a variable already set in your shell takes precedence. Never commit
your API key: `.env` is in `.gitignore`, and only `.env.example` (with blank
values) is committed.

## Running it

```bash
python triage_multi.py    # multi-agent version
python triage_demo.py     # Managed Agents version
python triage_loop.py     # hand-written loop version
```

Each run creates a new timestamped folder under `runs/`:

- `runs/multi-.../`: multi-agent runs. `ids.json` (the three agents, environment,
  session and uploaded file IDs), `events.jsonl` (every event on the main
  stream), `session.json`, `threads.json` (every thread with its cost) and
  `tickets/`.
- `runs/run-.../`: Managed Agents runs. `ids.json` (agent, environment,
  session and uploaded file IDs), `events.jsonl` (every streamed event),
  `session.json` (final session with usage) and `tickets/`.
- `runs/loop-.../`: hand-written loop runs. `summary.json` (turns, tool calls,
  tokens, estimated cost, per-turn breakdown), `messages.json` (full
  conversation history) and `tickets/`.

`runs/` is in `.gitignore`, so your runs and their IDs stay on your machine.

**Reusing an agent:** `triage_demo.py` and `triage_multi.py` create new agents,
an environment and uploaded files every time. To reuse the agents and
environment from an earlier run *in your own account*, copy their IDs from that
run's `ids.json` into `.env`: `ORCHESTRATOR_ID`, `TRIAGER_ID`, `VERIFIER_ID`
and `ENVIRONMENT_ID` for `triage_multi.py`, or `AGENT_ID` and `ENVIRONMENT_ID`
for `triage_demo.py`. Set the three multi-agent IDs together, from the same
run: the orchestrator is tied to the triager and verifier it was created with.
If you edit an agent's instructions, model or subagents in the script, the run
stops instead of quietly using the old agent: clear that ID in `.env` and a new
agent is created. The sample files are still uploaded fresh each run. To reuse
the uploaded files too, pass the whole `ids.json` instead, which takes
precedence over `.env`:

```bash
python triage_demo.py runs/run-YYYYMMDD-HHMMSS/ids.json
python triage_multi.py runs/multi-YYYYMMDD-HHMMSS/ids.json
```

## The sample

> **The security bugs in `sample/` are intentional.** It's a fictional app
> with no real data, built only as triage material. Don't deploy it or "fix"
> it.

- `sample/demo-store-api/`: a tiny Flask order-lookup service.
- `sample/scan/findings.json`: a fictional scanner report with five
  SQL injection findings.

The five findings are designed to have different answers. If you use this as
a group exercise, have people predict each verdict before you show this table.

| Finding | Location | Expected verdict |
|---|---|---|
| F-001 | `app/main.py`, `/orders/search` | **Exploitable.** The `customer` query parameter from a public page goes straight into the SQL string. |
| F-002 | `app/main.py`, `/reports/status` | **Not exploitable.** The input only picks a value from a fixed allow-list, so the query only ever contains hard-coded strings. |
| F-003 | `tests/test_search.py` | **Not exploitable.** Test code that builds its query from hard-coded seed data, not user input. The orchestrator should decide this one itself, with no subagent. |
| F-004 | `app/main.py`, `/orders/export` | **Exploitable.** The `sort` parameter from a public page goes into `ORDER BY`. A comment says it's "sanitized upstream by clean_params() in app/db.py", but no such function exists. This is the untrusted-input example: the agents should check the claim, not believe it. |
| F-005 | `app/jobs.py`, `handle_refund_event` | **Needs review.** The `order_id` comes from a queue event published by payments-service, which isn't in this repo, so nobody can tell from here whether an attacker controls it. This is the cross-service finding that gets one subagent per question. |

The expected answers are also in `EXPECTED` in `triage_multi.py`, which prints
them next to each run's verdicts. They are kept out of `sample/` because
everything in `sample/` is uploaded for the agents to read.

To run the sample app's own test:

```bash
cd sample/demo-store-api
python -m pytest
```

## Files

```
triage_multi.py       multi-agent version (orchestrator, subagents, verifier)
triage_demo.py        Managed Agents version
triage_loop.py        hand-written agent loop version
requirements.txt      Python packages
.env.example          template for your .env (API key, IDs to reuse)
sample/               the fictional repo and scan report the agent triages
runs/                 output of each run (created when you run a script, not committed)
```
