"""The attack suite is the security test suite.

Each attack must succeed without controls AND be blocked with them. New attacks
are added here as their phase lands.
"""

from __future__ import annotations

import pytest

from attacks import ATTACKS


def _check(result):
    assert result.succeeded_without_controls, (
        f"{result.name}: attack should succeed with controls OFF (otherwise the test proves nothing)"
    )
    assert result.blocked_with_controls, (
        f"{result.name}: {result.control} should block the attack with controls ON"
    )


@pytest.mark.parametrize("module", ATTACKS, ids=[m.__name__.split(".")[-1] for m in ATTACKS])
def test_attack_blocked(module):
    _check(module.run())
