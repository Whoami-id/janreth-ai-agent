"""Ethical, in-process attack harness for Janreth.

Educational only. Every attack runs against an agent this harness builds in
memory, driven by a scripted (offline) LLM and fake tools - never a real model
endpoint or a real-world target. The pattern: build the victim agent twice,
controls OFF (the attack succeeds) and controls ON (the attack is blocked), and
assert the difference. These same modules are the security test suite.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from janreth.llm import LlmResponse
from janreth.types import Message, ToolCall, ToolResult

ETHICAL_NOTE = (
    "Educational only. Runs against the framework's own in-process sandboxed "
    "agents. No operational attack guidance against third-party systems."
)


class ScriptedLlm:
    """Offline LLM stand-in: returns queued responses in order. No network."""

    def __init__(self, responses, model: str = "scripted/offline"):
        self.model = model
        self._responses = list(responses)

    async def generate(self, request):
        if not self._responses:
            return LlmResponse(content=[Message(role="assistant", content="(end of script)")])
        return self._responses.pop(0)


def tool_call(name: str, call_id: str = "c1", **arguments) -> LlmResponse:
    """A scripted LLM turn that calls one tool."""
    return LlmResponse(content=[ToolCall(tool_call_id=call_id, name=name, arguments=arguments)])


def final(text: str) -> LlmResponse:
    """A scripted LLM turn that ends with a plain answer."""
    return LlmResponse(content=[Message(role="assistant", content=text)])


def transcript_text(context) -> str:
    """All message/tool-call/tool-result text in the run, joined for inspection."""
    parts: list[str] = []
    for event in context.events:
        for item in event.content:
            if isinstance(item, Message):
                parts.append(item.content)
            elif isinstance(item, ToolResult):
                parts.append(" ".join(str(c) for c in item.content))
            elif isinstance(item, ToolCall):
                parts.append(str(item.arguments))
    return "\n".join(parts)


def run_agent(agent, user_input: str = "please proceed"):
    """Run an agent to completion synchronously (no event loop required)."""
    return asyncio.run(agent.run(user_input=user_input))


@dataclass
class AttackResult:
    """The outcome of one attack run, controls off vs on."""

    name: str
    summary: str
    codes: str  # e.g. "ASI02 / T2"
    control: str  # the control it validates
    succeeded_without_controls: bool
    blocked_with_controls: bool
    detail: str = ""

    @property
    def passed(self) -> bool:
        """The attack must succeed without controls AND be blocked with them."""
        return self.succeeded_without_controls and self.blocked_with_controls

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        return (
            f"[{mark}] {self.name:26} {self.codes:16} "
            f"off_succeeds={self.succeeded_without_controls!s:5} "
            f"on_blocked={self.blocked_with_controls!s:5}  -> {self.control}"
        )
