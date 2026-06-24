"""Run the Janreth attack suite: ``python -m attacks``."""

from __future__ import annotations

from attacks import ATTACKS, run_all
from attacks.runner import ETHICAL_NOTE


def main() -> int:
    print(ETHICAL_NOTE)
    print()
    blocked = 0
    for result in run_all():
        print(result.line())
        blocked += 1 if result.passed else 0
    print()
    print(f"{blocked}/{len(ATTACKS)} attacks blocked by their control.")
    return 0 if blocked == len(ATTACKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
