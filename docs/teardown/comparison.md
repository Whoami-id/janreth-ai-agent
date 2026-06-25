# Teardown — Janreth assessed by the Janreth GCC Platform

An independent agentic-threat assessment of this framework, run through the live
Janreth GCC Platform (janreth.com) twice: **Pass A** with the security controls
described as off, **Pass B** with the default-on control set. The platform sees
only a prose description — it has no access to janreth's code — so the reduction
below is an outside measurement, not a self-graded one. Reports: `Pass A.pdf`,
`Pass B.pdf` (ADGM, 2026-06-25).

## Headline

| Metric | Pass A (raw) | Pass B (hardened) | Change |
|---|---|---|---|
| HIGH-severity findings | 5 | 1 | −80% |
| Total findings | 10 | 8 | two eliminated |
| MAESTRO layers with findings | 6 | 4 | −2 |
| Regulatory exposure | 5 High / 5 Moderate | 1 High / 7 Moderate | 4 High → Moderate |
| Binding obligations triggered | 36 | 32 | −4 |
| Composite posture | 10.0 Critical | 10.0 Critical | unchanged (honest — see note) |

> **Why composite stays Critical:** the platform anchors on the worst finding,
> and code/command execution remains HIGH (sandbox escape needs a second bug).
> The controls reduce risk; they do not make the framework "safe." Honest by design.

## Per-finding: what each control did

| Pass A finding (raw) | janreth control | Pass B outcome | Attack that proves it |
|---|---|---|---|
| Prompt injection via external content — **HIGH** | InjectionScreen | **MEDIUM** ("screening is applied") | a01, a02 |
| Model-controlled code/bash execution — **HIGH** | SandboxPolicy + ConfirmationPolicy | **HIGH** but bounded ("egress denial + confirmation — CRITICAL→HIGH") | a05, a09 |
| No human-in-the-loop approval — MEDIUM | ConfirmationPolicy | **eliminated** (confirmation now required) | a09 |
| Memory poisoning (ChromaDB) — **HIGH** | MemoryGuard | **MEDIUM** ("neutralized/enveloped") | a06 |
| RAG retrieval injection — MEDIUM | InjectionScreen / OutputSanitizer | MEDIUM (residual: corpus write-side) | a02 |
| Full conversation inherited on handoff — MEDIUM | ScopeToken | MEDIUM (residual: scope limits privilege, not context leakage) | a07 |
| Unverified remote A2A peer replies — **HIGH** | AgentIdentity (A2A signing) | **MEDIUM** ("signed messages authenticate peers") | a07 |
| External MCP servers — **HIGH** | ToolProvenance | **MEDIUM** ("allow-list + provenance recording") | — |
| Provider API key secrets — MEDIUM | Redactor | MEDIUM (residual: env store reachable) | a08 |
| File/upload reads local files — MEDIUM | ToolPolicyGate + ConfirmationPolicy | **eliminated** (writes need confirmation) | a04, a09 |

Four HIGH findings dropped to MEDIUM, one was bounded with explicit reasoning,
and two findings were eliminated outright.

## Honest residuals (these match janreth's README "what this does NOT protect against")

- **Code execution stays HIGH** — the sandbox is the boundary; janreth adds policy on top.
- **RAG corpus poisoning** — janreth sanitizes on read, not the write side of an external corpus.
- **Context leakage on handoff** — ScopeToken narrows *privilege*, not what conversation a handoff carries.
- **Env secret store** — the Redactor protects outputs; it does not relocate the keys out of the environment.

That the platform's residual findings line up with janreth's own stated limits is
itself the integrity check: nothing is over-claimed on either side.

## The corroborating proof

The platform measures the *design*; the attack suite proves each control actually
blocks its attack at runtime:

```
python -m attacks   ->   10/10 attacks blocked by their control
```

## The claim

The threats an independent agentic-threat assessment flags in the raw framework
are the threats janreth's controls measurably reduce in the hardened one — and the
attack suite proves each control blocks the matching attack. The app shows the
danger; the framework shows the cure; both speak the same OWASP/MAESTRO language.
