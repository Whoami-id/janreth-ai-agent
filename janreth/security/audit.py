"""AuditTrail - a tamper-evident security log over the agent's event stream.

The agent already records every LLM response, tool call, and tool result as an
Event (janreth/types.py). AuditTrail adds a parallel, append-only, hash-chained
record of security-relevant actions on the ExecutionContext, so a run leaves a
trail that cannot be edited, reordered, or truncated after the fact without
detection (each entry's hash covers the previous entry's hash).

Seam: ExecutionContext.state + the before/after callback hooks.
Maps to: T8 Repudiation & Untraceability - MAESTRO Evaluation & Observability -
STRIDE Repudiation - KC2/KC6.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from janreth.security.taxonomy import ControlSpec, register

SPEC = register(
    ControlSpec(
        key="audit_trail",
        name="AuditTrail",
        summary="Append-only, hash-chained log of security actions over the event stream.",
        seam="ExecutionContext.state + before/after callbacks",
        tcodes=("T8",),
        maestro=("Evaluation & Observability",),
        stride=("Repudiation",),
        kc=("KC2", "KC6"),
    )
)

_STATE_KEY = "janreth_audit"
_GENESIS = "0" * 64
# Fields hashed into the chain (entry_hash itself is excluded).
_PAYLOAD_FIELDS = (
    "seq",
    "timestamp",
    "control",
    "action",
    "decision",
    "detail",
    "tcodes",
    "prev_hash",
)


def _entry_hash(prev_hash: str, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditTrail:
    """A view over the append-only audit entries stored on the context."""

    def __init__(self, entries: list[dict]):
        self._entries = entries

    def record(
        self,
        control: str,
        action: str,
        *,
        decision: str = "observe",
        detail: dict | None = None,
        tcodes: tuple[str, ...] = (),
    ) -> dict:
        """Append a hash-chained audit entry and return it."""
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else _GENESIS
        payload = {
            "seq": len(self._entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "control": control,
            "action": action,
            "decision": decision,
            "detail": detail or {},
            "tcodes": list(tcodes),
            "prev_hash": prev_hash,
        }
        entry = {**payload, "entry_hash": _entry_hash(prev_hash, payload)}
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    def verify(self) -> bool:
        """True iff the chain is intact (no entry edited, inserted, or reordered)."""
        prev_hash = _GENESIS
        for index, entry in enumerate(self._entries):
            if entry.get("seq") != index or entry.get("prev_hash") != prev_hash:
                return False
            payload = {field: entry.get(field) for field in _PAYLOAD_FIELDS}
            if _entry_hash(prev_hash, payload) != entry.get("entry_hash"):
                return False
            prev_hash = entry["entry_hash"]
        return True


def get_audit(context) -> AuditTrail:
    """Return the AuditTrail bound to this context, creating the log if needed."""
    entries = context.state.setdefault(_STATE_KEY, [])
    return AuditTrail(entries)


# --- Observer callbacks: record only, never short-circuit (return None) ---


def audit_before_llm(context, llm_request):
    get_audit(context).record(
        SPEC.name,
        "llm_request",
        detail={
            "tool_choice": llm_request.tool_choice,
            "tools": [t.name for t in (llm_request.tools or [])],
        },
    )
    return None


def audit_before_tool(context, tool_call):
    get_audit(context).record(
        SPEC.name,
        "tool_call",
        detail={"tool": tool_call.name, "arg_keys": sorted(tool_call.arguments.keys())},
    )
    return None


def audit_after_tool(context, tool_result):
    get_audit(context).record(
        SPEC.name,
        "tool_result",
        decision=tool_result.status,
        detail={"tool": tool_result.name},
    )
    return None
