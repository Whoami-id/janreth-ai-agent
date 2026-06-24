"""Unit tests for controls whose core is a static check, not the agent loop."""

from __future__ import annotations

from janreth.security.identity import ScopeToken, sign, verify
from janreth.security.provenance import is_trusted_mcp
from janreth.security.sandbox import scan_code


def test_scope_narrow_cannot_widen():
    root = ScopeToken(frozenset({"a", "b"}))
    narrowed = root.narrow({"a", "c"})  # request a + c -> only a survives
    assert narrowed.allowed_tools == frozenset({"a"})
    assert narrowed.allows("a")
    assert not narrowed.allows("c")
    # Narrowing again can never regain the dropped capability.
    assert "b" not in (narrowed.narrow({"a", "b"}).allowed_tools or set())


def test_a2a_signature_rejects_forgery():
    key = "shared-secret"
    payload = "transfer 100 to alice"
    good = sign(payload, key)
    assert verify(payload, good, key)
    assert not verify(payload, "deadbeef", key)  # forged signature
    assert not verify("transfer 100 to mallory", good, key)  # tampered payload


def test_trusted_mcp_allowlist():
    trusted = {"npx @official/mcp-server"}
    assert is_trusted_mcp("npx @official/mcp-server", trusted)
    assert not is_trusted_mcp("npx @evil/mcp-server", trusted)


def test_sandbox_scan_flags_egress():
    assert scan_code("import urllib.request; urllib.request.urlopen('http://x')") is not None
    assert scan_code("print(2 + 2)") is None
