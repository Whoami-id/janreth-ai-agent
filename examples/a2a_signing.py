"""A2A message signing — how janreth authenticates inter-agent replies.

Runs offline. Shows the HMAC handshake that AgentExecutorImpl (the A2A server,
a2a_server.py) and RemoteAgent (the A2A client, remote.py) use: a reply signed
with the shared key verifies, while a forged or tampered reply is rejected. Set
the same JANRETH_A2A_SHARED_KEY on both sides to enforce this on real traffic.
"""

from __future__ import annotations

from janreth.security import sign, verify

SHARED_KEY = "shared-secret-set-via-JANRETH_A2A_SHARED_KEY"


def main() -> None:
    reply = "transfer approved for invoice #4471"

    # Server side (AgentExecutorImpl): sign the artifact text before sending.
    signature = sign(reply, SHARED_KEY)
    print("genuine reply verifies:   ", verify(reply, signature, SHARED_KEY))

    # Client side (RemoteAgent): a tampered reply fails verification.
    tampered = "transfer approved for invoice #9999"
    print("tampered reply verifies:  ", verify(tampered, signature, SHARED_KEY))

    # A peer that does not hold the key cannot forge a valid signature.
    forged = sign(reply, "attacker-guess")
    print("forged signature verifies:", verify(reply, forged, SHARED_KEY))


if __name__ == "__main__":
    main()
