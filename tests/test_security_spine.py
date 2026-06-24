"""Phase 1 verification: the security spine (secure_defaults + AuditTrail).

These run with a scripted fake LLM - no API key or network needed.
"""

from __future__ import annotations

import asyncio

from janreth import Agent, tool
from janreth.llm import LlmResponse
from janreth.types import Message, ToolCall
from janreth.security import coverage, get_audit, secure_defaults


class FakeLlm:
    """A scripted LLM client (no network) that returns queued responses in order."""

    def __init__(self, responses: list[LlmResponse], model: str = "fake/model"):
        self.model = model
        self._responses = list(responses)

    async def generate(self, request):
        return self._responses.pop(0)


@tool
def echo(text: str) -> str:
    """Echo the given text back."""
    return f"echo: {text}"


def _build_agent() -> Agent:
    # Turn 1: call the echo tool. Turn 2: give a final answer.
    responses = [
        LlmResponse(content=[ToolCall(tool_call_id="c1", name="echo", arguments={"text": "hi"})]),
        LlmResponse(content=[Message(role="assistant", content="done")]),
    ]
    return Agent(model=FakeLlm(responses), tools=[echo], **secure_defaults())


def test_secure_defaults_runs_and_audits():
    agent = _build_agent()
    result = asyncio.run(agent.run(user_input="hi"))

    assert result.output == "done"
    audit = get_audit(result.context)
    actions = [entry["action"] for entry in audit.entries]
    assert "llm_request" in actions
    assert "tool_call" in actions
    assert "tool_result" in actions
    assert audit.verify() is True


def test_audit_chain_detects_tampering():
    result = asyncio.run(_build_agent().run(user_input="hi"))
    assert get_audit(result.context).verify() is True

    # Edit a recorded entry: the hash chain must now fail verification.
    result.context.state["janreth_audit"][0]["detail"] = {"tampered": True}
    assert get_audit(result.context).verify() is False


def test_taxonomy_coverage_includes_audit():
    cov = coverage()
    assert "T8" in cov["tcodes"]
    assert "Repudiation" in cov["stride"]


if __name__ == "__main__":
    test_secure_defaults_runs_and_audits()
    test_audit_chain_detects_tampering()
    test_taxonomy_coverage_includes_audit()
    print("PHASE 1 OK")
