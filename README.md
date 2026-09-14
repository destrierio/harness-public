# destrier-harness

A powerful autonomous pentest harness for the Destrier cyber range. It drops into
a sealed Kali attacker cell, works the target with a phase-aware methodology, and
captures per-run `destrier{...}` flags. It is deliberately deep in **binary
exploitation (heap + ROP)** and strong on **web** and **known-CVE** exploitation.

You do not need to write code to compete: edit one file, `config.yaml`, then build
and submit.

For the mini CTF, start with the [participant guide](docs/PARTICIPANTS.md).
[config.yaml](config.yaml) preserves the starter's supporting prompt instructions
and supplies numbered placeholders for your own methodology. Models use the
event default; all roles start at temperature `0.5` with provider-default reasoning
effort. Context, tool settings and automatic strategy hints retain their working
values. [config.participant.yaml](config.participant.yaml) is the
reset copy.

![High-level map of the Destrier harness: the run loop from plan to flag, plus shared memory, context helpers and the skill library](docs/harness-overview.png)

Diagram: [PNG](docs/harness-overview.png). The editable Mermaid source lives in the [participant guide](docs/PARTICIPANTS.md).

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install pytest PyYAML unicorn capstone
make test                 # unit + offline end-to-end (no Docker, no internet)
$EDITOR config.yaml       # write your methodology in the marked prompt areas
boxr agent build .        # bake config + agent into the linux/amd64 image
boxr agent submit .       # push and record the version
```

## How it works

- **Orchestrator + specialists.** A strategist loop runs the methodology (recon →
  enumerate → foothold → escalate → loot) and delegates bounded goals to
  short-lived specialist sub-agents — `recon`, `web`, `pwn`, `privesc` — that work
  in isolated context and report structured findings back.
- **Shared Knowledge Base.** Every fact (services, findings, credentials,
  footholds, artifacts, flags) lands in one structured store, rendered as a
  compact SITUATION digest each turn, so the agent reads current state instead of
  re-deriving it from a long transcript.
- **On-demand skills.** A library of markdown playbooks (`skills/`, deepest on
  pwn) is loaded only when needed via `consult_skill`, keeping context lean.
- **Rich tools.** `shell`, persistent PTY `session`s (hold a foothold shell,
  gdb, msfconsole), a `reverse_shell_listener`, a pwntools-ready `python_exec`
  kernel, a stateful `http_request` client, `fetch_artifact` into a workspace, and
  a headless `browser`.
- **No artificial limits.** The run ends only on the platform's cost cap, the
  wall-clock deadline, or full capture — never a turn or step count. The agent is
  budget-aware only to shift behaviour, never to stop itself.

## The one file you edit: `config.yaml`

Prompts come first: replace the `1.`, `2.`, `3.` placeholders with your workflow,
decision rules and working guidelines. Keep the surrounding original instructions,
including concrete tool usage, environment workarounds, specialist guidance and
flag submission. Supplied support sections explain durable notes and the installed
binary-analysis helpers. Models, sampling, strategy/context and tools follow.
Sampling uses one baseline for all seven roles: temperature `0.5` and effort
`null`. Automatic hints and skill playbooks still apply alongside your prompts.
The `models` section lists all seven roles. Replace each `auto` with a permitted
model ID or a priority list to choose its model.
Unknown or forbidden names fall back to
the run default; numeric settings still need valid values. `make lint` is an optional platform-developer check that requires the separate
protocol checkout at `../protocol`; it checks the manifest, not this configuration. See the
[participant guide](docs/PARTICIPANTS.md) for validation and reset instructions.

The whole `skills/` library is also yours to extend — add or edit a playbook to
teach the harness a new technique without touching code.

## Layout

```
config.yaml  participant methodology areas and working configuration defaults
config.participant.yaml  starter reset copy
docs/        participant guide and the overview diagram (Mermaid + PNG)
harness/     the agent: runtime, config, gateway, flags, kb, tools, sessions,
             python kernel, http client, workspace, skills, subagents, loop
skills/      30 markdown playbooks (pwn / web / recon / post-ex / meta)
testrig/     offline mock gateway + vulnerable targets + local runners
tests/       unit + offline e2e (a gated container pwn e2e under DH_DOCKER_E2E=1)
Dockerfile   builds FROM harness-base with the full baked toolchain
```

## Testing

```bash
make test                              # offline suite, no Docker needed
DH_DOCKER_E2E=1 python3 -m pytest tests/e2e/test_pwn_container.py   # real pwntools capture
python3 -m testrig.run_local           # watch offline captures (web/session/delegate)
```

The offline rig loads `config.yaml` using the same discovery as the entrypoint
(`HARNESS_CONFIG` can select another file). It runs scripted model replies against
local targets; the capture and no-capture checks verify wiring, not prompt quality.
The suite also checks all seven role prompts and sampling settings at the model
request boundary, plus tool switches and output limits.
