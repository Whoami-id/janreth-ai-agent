"""Janreth security layer - controls on by default.

Two entry points:

    from janreth.security import secure_agent
    agent = secure_agent(model=..., tools=[...])          # recommended

    from janreth import Agent
    from janreth.security import secure_defaults
    agent = Agent(model=..., tools=[...], **secure_defaults())  # callbacks only

`secure_agent()` also applies the ConfirmationPolicy to the tools (the one
control that must set tool metadata rather than a callback) and, optionally, a
delegation ScopeToken. Every control hooks an existing Agent seam and maps to the
OWASP/MAESTRO taxonomy in janreth/security/taxonomy.py - which both the README
coverage matrix and the attack suite read from.
"""

from __future__ import annotations

from janreth.security import audit as _audit
from janreth.security import injection as _injection
from janreth.security import provenance as _provenance  # noqa: F401 (registers control)
from janreth.security import redaction as _redaction
from janreth.security import sandbox as _sandbox
from janreth.security import sanitize as _sanitize
from janreth.security.audit import (
    AuditTrail,
    audit_after_tool,
    audit_before_llm,
    audit_before_tool,
    get_audit,
)
from janreth.security.confirmation import apply_confirmation_policy, is_high_impact
from janreth.security.identity import (
    ScopeToken,
    get_scope,
    scope_gate,
    set_scope,
    sign,
    verify,
)
from janreth.security.injection import injection_after_tool, injection_before_llm
from janreth.security.policy import ToolPolicy, default_policy, policy_gate
from janreth.security.provenance import is_trusted_mcp, tool_origins
from janreth.security.redaction import redactor_after_tool, redactor_before_llm
from janreth.security.sandbox import sandbox_policy_before_tool
from janreth.security.sanitize import memory_guard_after_tool, sanitizer_after_tool
from janreth.security.taxonomy import CONTROLS, ControlSpec, coverage

__all__ = [
    "secure_defaults",
    "secure_agent",
    "get_audit",
    "AuditTrail",
    "ToolPolicy",
    "default_policy",
    "policy_gate",
    "apply_confirmation_policy",
    "is_high_impact",
    "ScopeToken",
    "scope_gate",
    "set_scope",
    "get_scope",
    "sign",
    "verify",
    "is_trusted_mcp",
    "tool_origins",
    "CONTROLS",
    "ControlSpec",
    "coverage",
    # Individual control callbacks (for hand-wiring via Agent(**...) or audits)
    "audit_before_llm",
    "audit_before_tool",
    "audit_after_tool",
    "injection_before_llm",
    "injection_after_tool",
    "redactor_before_llm",
    "redactor_after_tool",
    "sandbox_policy_before_tool",
    "sanitizer_after_tool",
    "memory_guard_after_tool",
]


def secure_defaults(policy: ToolPolicy | None = None) -> dict:
    """Return the default security control bundle as Agent callback kwargs.

    Per seam the AuditTrail observer runs first (recording every attempt before
    any enforcing control can short-circuit it), then the enforcing controls.
    Splat into an Agent: ``Agent(..., **secure_defaults())``. ConfirmationPolicy
    and ScopeToken are applied via ``secure_agent()``, not as default callbacks.
    """
    pol = policy or default_policy()
    return {
        "before_llm_callbacks": [
            _audit.audit_before_llm,
            _redaction.redactor_before_llm,
            _injection.injection_before_llm,
        ],
        "before_tool_callbacks": [
            _audit.audit_before_tool,
            policy_gate(pol),
            _sandbox.sandbox_policy_before_tool,
        ],
        "after_tool_callbacks": [
            _audit.audit_after_tool,
            _redaction.redactor_after_tool,
            _injection.injection_after_tool,
            _sanitize.sanitizer_after_tool,
            _sanitize.memory_guard_after_tool,
        ],
    }


def secure_agent(
    model,
    tools=None,
    *,
    policy: ToolPolicy | None = None,
    confirm_high_impact: bool = True,
    scope: ScopeToken | None = None,
    **agent_kwargs,
):
    """Build an Agent with Janreth's controls on by default.

    Applies the ConfirmationPolicy to the tools (high-impact tools require human
    confirmation), an optional delegation ScopeToken, and the secure_defaults()
    callbacks. Any caller-supplied callbacks are appended after the security ones.
    """
    from janreth.agent import Agent

    tool_list = list(tools or [])
    if confirm_high_impact:
        apply_confirmation_policy(tool_list)

    defaults = secure_defaults(policy=policy)
    if scope is not None:
        defaults["before_tool_callbacks"].append(scope_gate(scope))
    for key in ("before_llm_callbacks", "before_tool_callbacks", "after_tool_callbacks"):
        extra = list(agent_kwargs.pop(key, []) or [])
        agent_kwargs[key] = defaults[key] + extra

    return Agent(model=model, tools=tool_list, **agent_kwargs)
