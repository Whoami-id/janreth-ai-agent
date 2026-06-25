"""InjectionScreen - detect and neutralize prompt-injection instructions.

Two seams. before_llm_callbacks screens INBOUND user content; after_tool_callbacks
screens tool OUTPUT before it re-enters the prompt - the higher-value surface,
since indirect injection arrives through web search, file reads, MCP, or A2A
replies. Detection is rule-based and offline (deterministic for tests); on a
match the suspect phrase is neutralized in place. Verdicts are an
[advisory estimate] - a heuristic, not a guarantee.

Maps to: T6 Intent Breaking & Goal Manipulation, T12 Agent Communication
Poisoning - MAESTRO Foundation Models + Data Operations - ASI derived from the
T-codes (ASI01 / ASI06 / ASI07) - STRIDE Tampering - KC1, KC3.
"""

from __future__ import annotations

import re

from janreth.security.audit import get_audit
from janreth.security.taxonomy import ControlSpec, register
from janreth.types import Message, ToolResult

SPEC = register(
    ControlSpec(
        key="injection_screen",
        name="InjectionScreen",
        summary="Detect and neutralize instruction-override phrases in user input and tool output.",
        seam="before_llm_callbacks + after_tool_callbacks",
        tcodes=("T6", "T12"),
        maestro=("Foundation Models", "Data Operations"),
        stride=("Tampering",),
        kc=("KC1", "KC3"),
    )
)

# Instruction-override phrases (matched case-insensitively as substrings).
_MARKERS: tuple[str, ...] = (
    "ignore all previous instructions",
    "ignore previous instructions",
    "ignore the above",
    "disregard all previous",
    "disregard previous instructions",
    "disregard the above",
    "forget your instructions",
    "forget all previous",
    "you are now",
    "new instructions:",
    "system prompt:",
    "reveal your system prompt",
    "print your system prompt",
    "override your instructions",
    "do not follow your",
)
_MARKER_RES = [re.compile(re.escape(m), re.IGNORECASE) for m in _MARKERS]
_PLACEHOLDER = "[neutralized-instruction]"


def find_injection(text: str) -> list[str]:
    """Return the injection markers present in `text` (advisory estimate)."""
    return [m for m, pattern in zip(_MARKERS, _MARKER_RES) if pattern.search(text)]


def neutralize(text: str) -> tuple[str, list[str]]:
    """Replace any injection markers with an inert placeholder; return (text, found)."""
    found: list[str] = []
    for marker, pattern in zip(_MARKERS, _MARKER_RES):
        if pattern.search(text):
            found.append(marker)
            text = pattern.sub(_PLACEHOLDER, text)
    return text, found


def injection_before_llm(context, llm_request):
    """Neutralize injection in inbound user messages (mutates in place)."""
    hits: list[str] = []
    for item in llm_request.contents:
        if isinstance(item, Message) and item.role == "user":
            cleaned, found = neutralize(item.content)
            if found:
                item.content = cleaned
                hits.extend(found)
    if hits:
        get_audit(context).record(
            SPEC.name,
            "llm_request",
            decision="neutralized",
            detail={"markers": hits},
            tcodes=SPEC.tcodes,
        )
    return None


def injection_after_tool(context, tool_result):
    """Neutralize injection in tool output before it re-enters the prompt."""
    if not tool_result.content:
        return None
    hits: list[str] = []
    new_content = []
    for item in tool_result.content:
        if isinstance(item, str):
            cleaned, found = neutralize(item)
            hits.extend(found)
            new_content.append(cleaned)
        else:
            new_content.append(item)
    if not hits:
        return None
    get_audit(context).record(
        SPEC.name,
        "tool_result",
        decision="neutralized",
        detail={"tool": tool_result.name, "markers": hits},
        tcodes=SPEC.tcodes,
    )
    return ToolResult(
        tool_call_id=tool_result.tool_call_id,
        name=tool_result.name,
        status=tool_result.status,
        content=new_content,
    )
