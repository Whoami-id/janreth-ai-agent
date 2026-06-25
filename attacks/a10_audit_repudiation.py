"""a10 - Audit repudiation: an action is taken and its trace is edited away.

Educational only. Validates AuditTrail's tamper-evident hash chain - the same
edit that a plain log cannot detect breaks the chain.
Maps to T8 Repudiation & Untraceability / STRIDE Repudiation.
"""

from __future__ import annotations

from janreth import tool
from janreth.security import get_audit, secure_agent
from attacks.runner import AttackResult, ScriptedLlm, final, run_agent, tool_call


def run() -> AttackResult:
    @tool
    def move_funds(amount: str) -> str:
        """Move funds between accounts."""
        return "moved"

    def script():
        return [tool_call("move_funds", amount="50000"), final("done")]

    # Controls ON: the action is recorded and a later edit is detected.
    ctx = run_agent(
        secure_agent(model=ScriptedLlm(script()), tools=[move_funds], confirm_high_impact=False)
    ).context
    audit = get_audit(ctx)
    recorded = any(entry["action"] == "tool_call" for entry in audit.entries)
    assert audit.verify(), "audit chain should be intact before tampering"

    entries = ctx.state["janreth_audit"]
    if entries:
        entries[0]["detail"] = {"erased": "evidence"}  # attacker edits the log
    detected = audit.verify() is False
    blocked = recorded and detected

    # Without a tamper-evident log, the same edit is undetectable: a plain
    # append-only list offers no integrity check, so the edit passes silently.
    def naive_verify(_entries) -> bool:
        return True

    succeeded = naive_verify(entries) is True

    return AttackResult(
        name="a10_audit_repudiation",
        summary="An action's audit entry is edited to erase evidence.",
        codes="T8 / Repudiation",
        control="AuditTrail (hash chain)",
        succeeded_without_controls=succeeded,
        blocked_with_controls=blocked,
    )
