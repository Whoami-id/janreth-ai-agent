"""SandboxPolicy - constrain what sandboxed code may do.

Seam: before_tool_callbacks. Statically inspects the code/command argument of
code-execution tools (execute_python, bash_tool) for network egress before the
call reaches the sandbox, and denies it. Detection is a best-effort static
heuristic - an [advisory estimate]; the sandbox's own isolation (e.g. E2B)
remains the boundary, this adds policy on top.

Maps to: T11 Unexpected RCE and Code Attacks, T4 Resource Overload, T2 Tool
Misuse - MAESTRO Deployment & Infrastructure - ASI05 Unexpected Code Execution -
STRIDE Elevation of Privilege + Denial of Service - KC6.
"""

from __future__ import annotations

import re

from janreth.security.audit import get_audit
from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="sandbox_policy",
        name="SandboxPolicy",
        summary="Block network egress in sandboxed code/commands before they run.",
        seam="before_tool_callbacks",
        tcodes=("T2", "T4", "T11"),
        maestro=("Deployment & Infrastructure",),
        asi=("ASI05",),
        stride=("Elevation of Privilege", "Denial of Service"),
        kc=("KC6",),
    )
)

_CODE_ARGS = ("code", "command", "script", "cmd", "bash")
_EGRESS = re.compile(
    r"(?i)\b(curl|wget|nc|netcat|ncat|telnet|ssh|scp|sftp)\b"
    r"|urllib\.request|urlopen|requests\.(?:get|post|put|delete)"
    r"|httpx\.|http\.client|socket\.(?:socket|create_connection)|/dev/tcp/"
)


def scan_code(value: str) -> str | None:
    """Return a denial reason if the code attempts network egress, else None."""
    if _EGRESS.search(value):
        return "sandboxed code attempts network egress"
    return None


def sandbox_policy_before_tool(context, tool_call):
    for key, value in tool_call.arguments.items():
        if key.lower() in _CODE_ARGS and isinstance(value, str):
            reason = scan_code(value)
            if reason:
                get_audit(context).record(
                    SPEC.name,
                    "tool_call",
                    decision="denied",
                    detail={"tool": tool_call.name, "reason": reason},
                    tcodes=SPEC.tcodes,
                )
                return f"denied: {reason} (SandboxPolicy)"
    return None
