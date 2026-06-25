"""Redactor - replace secrets (and optional PII) with typed placeholders.

Seams: after_tool_callbacks (redact tool OUTPUT before it enters the transcript)
and before_llm_callbacks (last-chance redaction on the assembled prompt, so a
secret never leaves the process). Both are best-effort heuristics - any verdict
is an [advisory estimate].

Maps to: T2 Tool Misuse (exfiltration), T3 Privilege Compromise - MAESTRO Data
Operations + Security & Compliance - ASI02, ASI03 - STRIDE Information
Disclosure - KC4, KC5.
"""

from __future__ import annotations

import re

from janreth.security.audit import get_audit
from janreth.security.taxonomy import ControlSpec, register
from janreth.types import Message, ToolResult

SPEC = register(
    ControlSpec(
        key="redactor",
        name="Redactor",
        summary="Replace API keys, private keys, JWTs (and optional PII) with typed placeholders.",
        seam="after_tool_callbacks + before_llm_callbacks",
        tcodes=("T2", "T3"),
        maestro=("Data Operations", "Security & Compliance"),
        stride=("Information Disclosure",),
        kc=("KC4", "KC5"),
    )
)

# Always-on secret detectors. Order matters (most specific first).
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # KEY/SECRET/TOKEN/PASSWORD = value  ->  keep the name, redact the value.
    ("assigned_secret", re.compile(
        r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*)"
        r"(\s*[=:]\s*)['\"]?([A-Za-z0-9_\-./+]{6,})['\"]?"
    )),
]

# Opt-in PII detectors.
_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


def redact_text(text: str, *, pii: bool = False) -> tuple[str, dict[str, int]]:
    """Return (redacted_text, {label: count}). Secrets always; PII when pii=True."""
    counts: dict[str, int] = {}

    def _make_repl(label: str):
        def repl(match: re.Match) -> str:
            counts[label] = counts.get(label, 0) + 1
            if label == "assigned_secret":
                return f"{match.group(1)}{match.group(2)}<REDACTED:secret>"
            return f"<REDACTED:{label}>"
        return repl

    patterns = list(_SECRET_PATTERNS) + (list(_PII_PATTERNS) if pii else [])
    for label, pattern in patterns:
        text = pattern.sub(_make_repl(label), text)
    return text, counts


def _merge(into: dict[str, int], add: dict[str, int]) -> None:
    for key, value in add.items():
        into[key] = into.get(key, 0) + value


def redactor_after_tool(context, tool_result):
    """Redact secrets out of a tool result before it enters the transcript."""
    if not tool_result.content:
        return None

    totals: dict[str, int] = {}
    new_content = []
    for item in tool_result.content:
        if isinstance(item, str):
            redacted, counts = redact_text(item)
            _merge(totals, counts)
            new_content.append(redacted)
        else:
            new_content.append(item)

    if not totals:
        return None

    get_audit(context).record(
        SPEC.name,
        "tool_result",
        decision="redacted",
        detail={"tool": tool_result.name, "counts": totals},
        tcodes=SPEC.tcodes,
    )
    return ToolResult(
        tool_call_id=tool_result.tool_call_id,
        name=tool_result.name,
        status=tool_result.status,
        content=new_content,
    )


def redactor_before_llm(context, llm_request):
    """Last-chance redaction on the assembled prompt (mutates in place)."""
    totals: dict[str, int] = {}
    for item in llm_request.contents:
        if isinstance(item, Message):
            redacted, counts = redact_text(item.content)
            if counts:
                item.content = redacted
                _merge(totals, counts)
    if totals:
        get_audit(context).record(
            SPEC.name,
            "llm_request",
            decision="redacted",
            detail={"counts": totals},
            tcodes=SPEC.tcodes,
        )
    return None
