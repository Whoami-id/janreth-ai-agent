"""A2A server adapter: expose any janreth Agent as an A2A service.

AgentExecutorImpl wraps ANY Agent (not a specific problem domain). When a shared
HMAC key is configured (``JANRETH_A2A_SHARED_KEY`` or the ``shared_key``
argument) it signs each outgoing artifact with
``janreth.security.identity.sign``, so a RemoteAgent peer can verify the reply
came from this server — the other half of the A2A signing handshake in
``remote.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from janreth.config import a2a_shared_key
from janreth.security.identity import sign

if TYPE_CHECKING:
    from janreth.agent import Agent


class AgentExecutor:
    """Base class for A2A agent executors."""

    async def execute(self, context: Any, event_queue: Any) -> None:
        raise NotImplementedError


class AgentExecutorImpl(AgentExecutor):
    """Standard A2A executor wrapping any janreth Agent.

    Usage::

        executor = AgentExecutorImpl(your_agent)   # any Agent, any domain
        # register `executor` with your A2A server framework
    """

    def __init__(self, agent: "Agent", shared_key: str | None = None):
        self.agent = agent
        self._shared_key = shared_key or a2a_shared_key()

    async def execute(self, context: Any, event_queue: Any) -> None:
        """Run the wrapped agent and push a (signed) artifact to the queue."""
        user_input = ""
        if hasattr(context, "message"):
            for part in context.message.get("parts", []):
                if part.get("type") == "text":
                    user_input = part["text"]
                    break

        result = await self.agent.run(user_input=user_input)

        if event_queue and result.output:
            text = str(result.output)
            artifact: dict[str, Any] = {
                "type": "artifact",
                "parts": [{"type": "text", "text": text}],
            }
            if self._shared_key:
                artifact["signature"] = sign(text, self._shared_key)
            await event_queue.put(artifact)
