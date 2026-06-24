"""AgentIdentity, ScopeToken, and A2A message signing.

Two related controls for multi-agent work:

- ScopeToken: a capability set (allowed tool names) that can only NARROW as work
  is delegated to a sub-agent or transferred - a delegated agent can never gain a
  capability its delegator lacked (the confused-deputy case). scope_gate()
  enforces it on the before_tool seam.
- A2A signing: sign() / verify() (HMAC-SHA256) for agent-to-agent messages, so a
  rogue peer's forged reply is rejected. The framework's RemoteAgent does no
  verification today; this control closes that gap.

Maps to: T9 Identity Spoofing, T13 Rogue Agents, T16 Insecure Inter-Agent
Protocol Abuse, T3 Privilege Compromise - MAESTRO Agent Ecosystem + Security &
Compliance - ASI03, ASI07, ASI10 - STRIDE Spoofing + Elevation of Privilege - KC2.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from janreth.security.audit import get_audit
from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="agent_identity",
        name="AgentIdentity",
        summary="Narrowing-only delegation scope (ScopeToken) and signed agent-to-agent messages.",
        seam="ExecutionContext scope + before_tool + A2A sign/verify",
        tcodes=("T3", "T9", "T13", "T16"),
        maestro=("Agent Ecosystem", "Security & Compliance"),
        asi=("ASI03", "ASI07", "ASI10"),
        stride=("Spoofing", "Elevation of Privilege"),
        kc=("KC2",),
    )
)

_SCOPE_KEY = "janreth_scope"


@dataclass(frozen=True)
class ScopeToken:
    """Allowed tool names for an agent. None means unrestricted (root)."""

    allowed_tools: frozenset[str] | None = None

    def narrow(self, tools) -> "ScopeToken":
        """Return a token restricted to `tools`, intersected with the current scope.

        The result is always a subset of the current scope - delegation can only
        narrow capability, never widen it.
        """
        requested = frozenset(tools)
        if self.allowed_tools is None:
            return ScopeToken(requested)
        return ScopeToken(self.allowed_tools & requested)

    def allows(self, tool_name: str) -> bool:
        return self.allowed_tools is None or tool_name in self.allowed_tools


def set_scope(context, scope: ScopeToken) -> None:
    context.state[_SCOPE_KEY] = scope


def get_scope(context) -> ScopeToken | None:
    return context.state.get(_SCOPE_KEY)


def scope_gate(scope: ScopeToken):
    """Build a before_tool callback that denies tools outside `scope`."""

    def before_tool(context, tool_call):
        if not scope.allows(tool_call.name):
            get_audit(context).record(
                SPEC.name,
                "tool_call",
                decision="denied",
                detail={"tool": tool_call.name, "reason": "outside delegated scope"},
                tcodes=SPEC.tcodes,
            )
            return f"denied: tool {tool_call.name!r} is outside the delegated scope (ScopeToken)"
        return None

    return before_tool


# --- A2A message signing (closes the unverified-peer gap in remote.py) ---


def sign(payload: str, key: str) -> str:
    """HMAC-SHA256 signature for an agent-to-agent message payload."""
    return hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(payload: str, signature: str, key: str) -> bool:
    """Constant-time check that `signature` matches `payload` under `key`."""
    return hmac.compare_digest(sign(payload, key), signature or "")
