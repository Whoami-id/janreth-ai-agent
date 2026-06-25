"""ConfirmationPolicy - require human confirmation before high-impact tools run.

Seam: BaseTool.requires_confirmation + the agent's built-in suspend/resume. When
a tool has requires_confirmation=True, the agent pauses the run with
status='pending' and serializes the pending call; a later
run(tool_confirmations=[...]) resumes it. The flag exists in the framework but no
built-in tool sets it - this policy activates the dormant gate.

Maps to: T10 Overwhelming Human in the Loop - MAESTRO Security & Compliance -
ASI09 (derived from T10) - STRIDE Elevation of Privilege - KC2.
"""

from __future__ import annotations

from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="confirmation_policy",
        name="ConfirmationPolicy",
        summary="Require human confirmation before high-impact tools execute.",
        seam="BaseTool.requires_confirmation + agent suspend/resume",
        tcodes=("T10",),
        maestro=("Security & Compliance",),
        stride=("Elevation of Privilege",),
        kc=("KC2",),
    )
)

# Name fragments (substring, case-insensitive) for genuinely high-impact tools.
# Kept narrow so confirmation does not itself become a T10 over-prompting vector.
DEFAULT_HIGH_IMPACT: tuple[str, ...] = (
    "delete",
    "send_email",
    "execute_python",
    "bash",
    "shell",
    "upload_file",
    "write_file",
    "wire",
    "payment",
    "sql",
)


def is_high_impact(name: str, fragments: tuple[str, ...] = DEFAULT_HIGH_IMPACT) -> bool:
    lowered = name.lower()
    return any(fragment in lowered for fragment in fragments)


def apply_confirmation_policy(
    tools,
    *,
    fragments: tuple[str, ...] = DEFAULT_HIGH_IMPACT,
    names: set[str] | None = None,
) -> list:
    """Set requires_confirmation=True on high-impact tools (mutates in place).

    Pass `names` to gate an explicit set instead of the fragment heuristic.
    Returns the same list for convenience.
    """
    for tool in tools:
        if names is not None:
            if tool.name in names:
                tool.requires_confirmation = True
        elif is_high_impact(tool.name, fragments):
            tool.requires_confirmation = True
    return tools
