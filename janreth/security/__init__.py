"""Janreth security layer - controls on by default.

Two entry points:

    from janreth.security import secure_agent
    agent = secure_agent(model=..., tools=[...])          # recommended

    from janreth import Agent
    from janreth.security import secure_defaults
    agent = Agent(model=..., tools=[...], **secure_defaults())  # callbacks only

`secure_agent()` also applies the ConfirmationPolicy to the tools (the one
control that must set tool metadata rather than a callback). Every control hooks
an existing Agent seam and maps to the OWASP/MAESTRO taxonomy in
janreth/security/taxonomy.py - which both the README coverage matrix and the
attack suite read from.
"""

from __future__ import annotations

from janreth.security import audit as _audit
from janreth.security import policy as _policy
from janreth.security import redaction as _redaction
from janreth.security.audit import AuditTrail, get_audit
from janreth.security.confirmation import apply_confirmation_policy, is_high_impact
from janreth.security.policy import ToolPolicy, default_policy, policy_gate
from janreth.security.taxonomy import CONTROLS, ControlSpec, coverage

__all__ = [
    "secure_defaults",
    "secure_agent",
    "get_audit",
    "AuditTrail",
    "ToolPolicy",
    "default_policy",
    "apply_confirmation_policy",
    "is_high_impact",
    "CONTROLS",
    "ControlSpec",
    "coverage",
]


def secure_defaults(policy: ToolPolicy | None = None) -> dict:
    """Return the default security control bundle as Agent callback kwargs.

    Per seam the AuditTrail observer runs first (so it records every attempt
    before any enforcing control can short-circuit it), then the controls:
    ToolPolicyGate (before_tool) and Redactor (after_tool + before_llm).
    Splat into an Agent: ``Agent(..., **secure_defaults())``. ConfirmationPolicy
    is applied to the tools (not via a callback) - use ``secure_agent()``.
    """
    pol = policy or default_policy()
    return {
        "before_llm_callbacks": [_audit.audit_before_llm, _redaction.redactor_before_llm],
        "before_tool_callbacks": [_audit.audit_before_tool, policy_gate(pol)],
        "after_tool_callbacks": [_audit.audit_after_tool, _redaction.redactor_after_tool],
    }


def secure_agent(
    model,
    tools=None,
    *,
    policy: ToolPolicy | None = None,
    confirm_high_impact: bool = True,
    **agent_kwargs,
):
    """Build an Agent with Janreth's controls on by default.

    Applies the ConfirmationPolicy to the tools (high-impact tools require human
    confirmation) and attaches the secure_defaults() callbacks. Any caller-
    supplied callbacks are appended after the security ones.
    """
    from janreth.agent import Agent

    tool_list = list(tools or [])
    if confirm_high_impact:
        apply_confirmation_policy(tool_list)

    defaults = secure_defaults(policy=policy)
    for key in ("before_llm_callbacks", "before_tool_callbacks", "after_tool_callbacks"):
        extra = list(agent_kwargs.pop(key, []) or [])
        agent_kwargs[key] = defaults[key] + extra

    return Agent(model=model, tools=tool_list, **agent_kwargs)
