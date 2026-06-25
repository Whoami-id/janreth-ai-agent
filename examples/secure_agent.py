"""What a Janreth agent reads like - controls on by default.

This is the canonical example: one secure_agent() call wires the full control set
(audit, tool policy, confirmation, redaction, injection screening, sanitization,
sandbox egress, optional delegation scope). Run it with a real model + an
ANTHROPIC_API_KEY/OPENAI_API_KEY in your environment.
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv

from janreth import LlmClient, tool
from janreth.security import ScopeToken, ToolPolicy, get_audit, secure_agent

load_dotenv()  # load ANTHROPIC_API_KEY / OPENAI_API_KEY from a .env file


@tool
def lookup_policy(topic: str) -> str:
    """Look up an internal policy by topic."""
    return f"Policy for {topic}: follow the principle of least privilege."


@tool
def send_email(to: str, body: str) -> str:
    """Send an email (high-impact: gated by confirmation)."""
    return f"queued email to {to}"


async def main() -> None:
    agent = secure_agent(
        model=LlmClient("anthropic/claude-haiku-4-5-20251001"),
        tools=[lookup_policy, send_email],
        instructions="You are a careful assistant. Use tools when needed.",
        # Only these tools may run; send_email also requires human confirmation.
        policy=ToolPolicy(allow={"lookup_policy", "send_email"}),
        # Optional: narrow what a delegated step is allowed to do.
        scope=ScopeToken(frozenset({"lookup_policy", "send_email"})),
    )

    result = await agent.run(user_input="What is our policy on access control?")
    print("answer:", result.output)

    # Every decision is on a tamper-evident audit trail.
    audit = get_audit(result.context)
    print("audit entries:", len(audit.entries), "| chain intact:", audit.verify())


if __name__ == "__main__":
    asyncio.run(main())
