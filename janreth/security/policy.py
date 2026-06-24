"""ToolPolicyGate - default-deny tool allow-listing + argument constraints.

Seam: before_tool_callbacks (agent.py). A before-tool callback that returns a
non-None value short-circuits the tool: the agent records that value as the
result and never runs the tool. So a denial returns a reason string and the
call is blocked before execution.

Maps to: T2 Tool Misuse, T3 Privilege Compromise, T4 Resource Overload -
MAESTRO Agent Frameworks + Security & Compliance - ASI02, ASI03 -
STRIDE Elevation of Privilege - KC5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from janreth.security.audit import get_audit
from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="tool_policy_gate",
        name="ToolPolicyGate",
        summary="Default-deny tool allow-list, argument constraints, and per-tool call budgets.",
        seam="before_tool_callbacks",
        tcodes=("T2", "T3", "T4"),
        maestro=("Agent Frameworks", "Security & Compliance"),
        asi=("ASI02", "ASI03"),
        stride=("Elevation of Privilege",),
        kc=("KC5",),
    )
)

# Argument names commonly used to pass a filesystem path.
_PATH_ARG_NAMES = (
    "path", "file", "filename", "filepath", "file_path", "local_path",
    "dir", "directory", "sandbox_path",
)


def _looks_unsafe_path(value: str) -> bool:
    """[advisory estimate] True for path traversal / absolute / home-relative paths."""
    return ".." in value or value.startswith("/") or value.startswith("~")


def default_path_constraint(arguments: dict) -> str | None:
    """Flag any path-shaped argument that escapes a relative working directory."""
    for key, value in arguments.items():
        if key.lower() in _PATH_ARG_NAMES and isinstance(value, str) and _looks_unsafe_path(value):
            return f"argument {key!r} looks like an unsafe path: {value!r}"
    return None


@dataclass
class ToolPolicy:
    """A declarative tool-execution policy.

    - allow: if set, ONLY these tool names may run (default-deny everything else).
    - deny: tool names that may never run.
    - arg_constraints: per-tool checks; each returns a denial reason or None.
    - global_constraints: checks applied to every tool call.
    - max_calls_per_tool: per-run call budget (resource overload, T4).
    """

    allow: set[str] | None = None
    deny: set[str] = field(default_factory=set)
    arg_constraints: dict[str, Callable[[dict], str | None]] = field(default_factory=dict)
    global_constraints: list[Callable[[dict], str | None]] = field(default_factory=list)
    max_calls_per_tool: int | None = None

    def decision(self, context, tool_call) -> str | None:
        """Return a denial reason if the call is blocked, else None (allowed)."""
        name = tool_call.name
        args = tool_call.arguments

        if name in self.deny:
            return f"denied: tool {name!r} is on the deny-list"
        if self.allow is not None and name not in self.allow:
            return f"denied: tool {name!r} is not on the allow-list"

        for check in self.global_constraints:
            reason = check(args)
            if reason:
                return f"denied: {reason}"

        per_tool = self.arg_constraints.get(name)
        if per_tool is not None:
            reason = per_tool(args)
            if reason:
                return f"denied: {reason}"

        if self.max_calls_per_tool is not None:
            counts = context.state.setdefault("janreth_tool_call_counts", {})
            if counts.get(name, 0) >= self.max_calls_per_tool:
                return f"denied: call budget exceeded for {name!r}"
            counts[name] = counts.get(name, 0) + 1

        return None


def default_policy() -> ToolPolicy:
    """A usable secure default: no allow-list, but path-traversal blocked globally."""
    return ToolPolicy(global_constraints=[default_path_constraint])


def policy_gate(policy: ToolPolicy) -> Callable:
    """Build a before_tool callback that enforces `policy`."""

    def before_tool(context, tool_call):
        reason = policy.decision(context, tool_call)
        if reason is not None:
            get_audit(context).record(
                SPEC.name,
                "tool_call",
                decision="denied",
                detail={"tool": tool_call.name, "reason": reason},
                tcodes=SPEC.tcodes,
            )
            return reason  # non-None -> the agent skips the tool and uses this
        return None

    return before_tool
