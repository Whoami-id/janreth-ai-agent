"""Environment-driven configuration for the janreth framework.

Every getter reads ``os.environ`` at call time with a sensible default, so tests
and callers can override via the environment. Feature keys (A2A signing) return
``None`` when unset — unset means the feature is dormant, matching the
``JANRETH_*`` convention used across Janreth.
"""

from __future__ import annotations

import os

DEFAULT_EMBEDDING_MODEL = "text-embedding-3-small"


def embedding_model() -> str:
    """Embedding model for RAG + long-term memory (``JANRETH_EMBEDDING_MODEL``).

    The default is an OpenAI model; point it at any provider/model your embedding
    backend accepts to keep the framework provider-agnostic.
    """
    return os.getenv("JANRETH_EMBEDDING_MODEL", DEFAULT_EMBEDDING_MODEL)


def a2a_shared_key() -> str | None:
    """Shared HMAC key for A2A message signing (``JANRETH_A2A_SHARED_KEY``).

    ``None`` ⇒ signing/verification is dormant and inter-agent replies are NOT
    authenticated. Set it on both the server and the client to enforce signed A2A.
    """
    return os.getenv("JANRETH_A2A_SHARED_KEY")
