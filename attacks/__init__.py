"""Janreth red-team attack demos - each validates a control by being blocked.

Educational only (see attacks/runner.py:ETHICAL_NOTE). Every attack runs in
process against the framework's own sandboxed agents and a scripted offline LLM.
Run them all with ``python -m attacks`` or via the test suite.
"""

from __future__ import annotations

from attacks import (
    a03_tool_abuse,
    a04_privilege_escalation,
    a08_secret_exfil,
    a09_hitl_bypass,
)
from attacks.runner import AttackResult, ETHICAL_NOTE

ATTACKS = [
    a03_tool_abuse,
    a04_privilege_escalation,
    a08_secret_exfil,
    a09_hitl_bypass,
]


def run_all() -> list[AttackResult]:
    """Run every registered attack and return the results."""
    return [module.run() for module in ATTACKS]


if __name__ == "__main__":
    print(ETHICAL_NOTE)
    print()
    failures = 0
    for result in run_all():
        print(result.line())
        failures += 0 if result.passed else 1
    print()
    print(f"{len(ATTACKS) - failures}/{len(ATTACKS)} attacks blocked by their control.")
