"""Remote agent support via the A2A protocol.

RemoteAgent is the A2A *client*: it discovers a peer from its agent card and
sends JSON-RPC requests. When a shared HMAC key is configured
(``JANRETH_A2A_SHARED_KEY`` or the ``shared_key`` argument), every reply
artifact is verified with ``janreth.security.identity.verify`` before its text
is accepted — a forged or tampered peer reply is rejected, not returned.
"""

from __future__ import annotations

import logging

import httpx

from janreth.config import a2a_shared_key
from janreth.context import AgentResult, ExecutionContext
from janreth.security.identity import verify

logger = logging.getLogger(__name__)


class RemoteAgent:
    """Client for interacting with remote agents via the A2A protocol."""

    def __init__(self, base_url: str, shared_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.name = ""
        self.description = ""
        self._shared_key = shared_key or a2a_shared_key()
        self._load_agent_info()

    def _load_agent_info(self) -> None:
        """Load agent info from the remote server's agent card."""
        try:
            response = httpx.get(f"{self.base_url}/.well-known/agent.json")
            if response.status_code == 200:
                info = response.json()
                self.name = info.get("name", "remote_agent")
                self.description = info.get("description", "")
        except Exception:
            self.name = "remote_agent"

    def _artifact_text(self, artifact: dict) -> str:
        """Join an artifact's text parts, verifying its signature if a key is set.

        Raises ValueError if a shared key is configured but the artifact's
        signature is missing or does not match (an unauthenticated peer reply).
        """
        text = "\n".join(
            part["text"]
            for part in artifact.get("parts", [])
            if part.get("type") == "text"
        )
        if self._shared_key is not None:
            if not verify(text, artifact.get("signature"), self._shared_key):
                raise ValueError(
                    "A2A reply signature verification failed — the peer is "
                    "unauthenticated or the reply was tampered with"
                )
        else:
            logger.warning(
                "A2A reply from %s is NOT verified; set JANRETH_A2A_SHARED_KEY "
                "(here and on the server) to authenticate peer replies",
                self.base_url,
            )
        return text

    async def run(
        self,
        user_input: str,
        context: ExecutionContext | None = None,
        verbose: bool = False,
    ) -> AgentResult:
        """Send a request to the remote agent and return its (verified) reply."""
        if context is None:
            context = ExecutionContext()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/tasks/send",
                json={
                    "jsonrpc": "2.0",
                    "method": "tasks/send",
                    "params": {
                        "message": {
                            "role": "user",
                            "parts": [{"type": "text", "text": user_input}],
                        }
                    },
                },
                timeout=120.0,
            )

            result = response.json()
            parts: list[str] = []

            if "result" in result:
                task_result = result["result"]
                for artifact in task_result.get("artifacts", []):
                    parts.append(self._artifact_text(artifact))

            return AgentResult(output="\n".join(parts), context=context)
