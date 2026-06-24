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
    a06_memory_poisoning,
    a08_secret_exfil,
    a09_hitl_bypass,
)
from attacks.runner import AttackResult, ETHICAL_NOTE

ATTACKS = [
    a01_goal_hijack,
    a02_indirect_injection,
    a03_tool_abuse,
    a04_privilege_escalation,
    a06_memory_poisoning,
    a08_secret_exfil,
    a09_hitl_bypass,
]


def run_all() -> list[AttackResult]:
    """Run every registered attack and return the results."""
    return [module.run() for module in ATTACKS]
