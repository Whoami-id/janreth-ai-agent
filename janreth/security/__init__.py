"""Janreth security layer - controls on by default.

`secure_defaults()` returns the callback bundle to attach to an Agent:

    from janreth import Agent
    from janreth.security import secure_defaults
    agent = Agent(model=..., tools=..., **secure_defaults())

Security is opt-out, not opt-in. Each control hooks an existing Agent seam
(before_llm / before_tool / after_tool callbacks) and maps to the OWASP/MAESTRO
taxonomy in janreth/security/taxonomy.py.
"""

from __future__ import annotations

from janreth.security import audit as _audit
from janreth.security.audit import AuditTrail, get_audit
from janreth.security.taxonomy import CONTROLS, ControlSpec, coverage

__all__ = [
    "secure_defaults",
    "get_audit",
    "AuditTrail",
    "CONTROLS",
    "ControlSpec",
    "coverage",
]


def secure_defaults() -> dict:
    """Return the default security control bundle as Agent callback kwargs.

    Splat into an Agent: ``Agent(..., **secure_defaults())``. Currently wires the
    AuditTrail observer on every seam; later controls (policy, confirmation,
    injection, sanitize, redaction, sandbox, identity) attach here too. The
    AuditTrail observer runs first on each seam so it records every attempted
    action before any later control can short-circuit it.
    """
    return {
        "before_llm_callbacks": [_audit.audit_before_llm],
        "before_tool_callbacks": [_audit.audit_before_tool],
        "after_tool_callbacks": [_audit.audit_after_tool],
    }
