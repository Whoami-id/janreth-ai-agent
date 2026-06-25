# Janreth

An open-source Python agent framework that ships its security controls **on by
default** — and proves each one with a runnable attack the framework blocks.

Most agent frameworks leave security to you. Janreth wires a set of controls into
the agent's own execution seams, maps each to the OWASP Agentic / MAESTRO threat
model, and pairs every control with an attack demo that succeeds with the control
off and is blocked with it on. The attack suite is the test suite.

Built on `asyncio` + Pydantic + LiteLLM (any provider). No other agent framework
underneath.

## Security on by default

```python
from janreth import tool, LlmClient
from janreth.security import secure_agent

@tool
def lookup(topic: str) -> str:
    """Look up a fact."""
    return "..."

agent = secure_agent(model=LlmClient("claude-haiku-4-5-20251001"), tools=[lookup])
result = await agent.run(user_input="...")
```

`secure_agent()` attaches the controls below, requires human confirmation for
high-impact tools, and records every decision on a tamper-evident audit trail.
Security is opt-out, not opt-in. (For full control over the callback bundle, use
`Agent(..., **secure_defaults())`.)

## Controls and what they cover

Each control hooks an existing Agent seam and maps to the OWASP Agentic Threats
(T1–T17), the OWASP Agentic Top 10 (ASI), MAESTRO layers, STRIDE, and the OWASP
"Securing Agentic Applications" Key Components (KC). The mapping lives in one
place — `janreth/security/taxonomy.py` — and is validated against the source
tables, so a mistyped code fails fast. Regenerate this table with
`python scripts/coverage_matrix.py`.

Each control declares its T-codes; **its ASI codes are derived from those T-codes
via the OWASP crosswalk** (never hand-assigned), so they can't drift from OWASP.

| Control | Seam | T-codes → ASI (derived) |
|---|---|---|
| **ToolPolicyGate** | `before_tool_callbacks` | T2, T3, T4 → ASI02, ASI03, ASI04, ASI06 |
| **ConfirmationPolicy** | `BaseTool.requires_confirmation + suspend/resume` | T10 → ASI09 |
| **Redactor** | `after_tool_callbacks + before_llm_callbacks` | T2, T3 → ASI02, ASI03, ASI04 |
| **InjectionScreen** | `before_llm_callbacks + after_tool_callbacks` | T6, T12 → ASI01, ASI04, ASI06, ASI07 |
| **OutputSanitizer** | `after_tool_callbacks` | T12 → ASI04, ASI06, ASI07 |
| **MemoryGuard** | `after_tool_callbacks (memory-recall tools)` | T1 → ASI06 |
| **SandboxPolicy** | `before_tool_callbacks` | T2, T4, T11 → ASI02, ASI04, ASI05, ASI06 |
| **AgentIdentity / ScopeToken** | `ExecutionContext scope + before_tool + A2A sign/verify` | T3, T9, T13, T16 → ASI02, ASI03, ASI04, ASI07, ASI10 |
| **ToolProvenance** | `tool registration + MCP loading` | T17 → ASI04 |
| **AuditTrail** | `ExecutionContext.state + before/after callbacks` | T8 → ASI08, ASI09 |

**Coverage:** T-codes 13/17 · ASI 10/10 · STRIDE 6/6 · KC 6/6 · MAESTRO 7/8.

## Run the attacks

```
python -m attacks      # runs every demo: controls off -> succeeds, on -> blocked
```

```
[PASS] a01_goal_hijack        ASI01 / T6    off_succeeds=True  on_blocked=True  -> InjectionScreen
[PASS] a03_tool_abuse         ASI02 / T2    off_succeeds=True  on_blocked=True  -> ToolPolicyGate
[PASS] a05_rce_egress         ASI05 / T11   off_succeeds=True  on_blocked=True  -> SandboxPolicy
[PASS] a08_secret_exfil       T2 / Info     off_succeeds=True  on_blocked=True  -> Redactor
[PASS] a10_audit_repudiation  T8 / Repud.   off_succeeds=True  on_blocked=True  -> AuditTrail
... 10/10 attacks blocked by their control.
```

The attacks live in `attacks/` and double as the security test suite (`pytest`).
**They are educational only** and run entirely in process against the framework's
own sandboxed agents and a scripted offline LLM — no real model endpoint, no
real-world target, no operational attack guidance.

## What this does NOT protect against

Honesty matters more than a longer coverage list. The detectors (injection,
redaction, egress) are best-effort heuristics — an *advisory estimate*, not a
guarantee. Specifically:

- **Four threats have no runtime control here:** T5 (Cascading Hallucination),
  T7 (Misaligned & Deceptive Behaviors), T14 (Human Attacks on Multi-Agent
  Systems), and T15 (Human Manipulation) — model-alignment, reliability, and
  human-process concerns a wrapper can't enforce.
- Sandbox **isolation** is provided by the sandbox (e.g. E2B); SandboxPolicy adds
  policy on top, it is not the isolation boundary.
- A determined prompt-injection or novel obfuscation can evade rule-based
  screening. Treat these controls as defense in depth, not a perimeter.

## Install

```
uv sync                                  # or: pip install -e .
uv run pytest                            # the security test suite
uv run python -m attacks                 # the attack report
uv run python scripts/check_voice.py     # the voice/lexicon gate
```

Requires Python 3.13+. Set provider keys (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`)
to run a real agent; the tests and attacks need neither.

## Layout

```
janreth/
  agent.py  context.py  llm.py  types.py        # the ReAct core (LiteLLM-backed)
  tools/  memory/  rag.py  transfer.py  remote.py  workflows/
  security/        # the control set + taxonomy + secure_defaults/secure_agent
attacks/           # the ethical attack suite (== the security tests)
examples/          # secure_agent.py: what a Janreth agent reads like
scripts/           # coverage_matrix.py, check_voice.py
```

## Origins

Janreth's agent core began as the companion code to the book *Build an AI Agent
from Scratch* and was extended into a security-first framework: the controls,
the attack suite, the taxonomy, and the audit trail are the additions. Built by
[Janatan Tajik](https://janatantajik.com), founder of Janreth.
