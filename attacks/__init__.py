"""Janreth red-team attack demos - each validates a control by being blocked.

Educational only (see attacks/runner.py:ETHICAL_NOTE). Every attack runs in
process against the framework's own sandboxed agents and a scripted offline LLM.
Run them all with ``python -m attacks`` or via the test suite.
"""

from __future__ import annotations

from attacks import (
    a01_goal_hijack,
    a02_indirect_injection,
    a03_tool_abuse,
    a04_privilege_escalation,
    a05_rce_egress,
    a06_memory_poisoning,
    a07_rogue_agent,
    a08_secret_exfil,
    a09_hitl_bypass,
    a10_audit_repudiation,
)
from attacks.runner import AttackResult, ETHICAL_NOTE

ATTACKS = [
    a01_goal_hijack,
    a02_indirect_injection,
    a03_tool_abuse,
    a04_privilege_escalation,
    a05_rce_egress,
    a06_memory_poisoning,
    a07_rogue_agent,
    a08_secret_exfil,
    a09_hitl_bypass,
    a10_audit_repudiation,
]


def run_all() -> list[AttackResult]:
    """Run every registered attack and return the results."""
    return [module.run() for module in ATTACKS]
