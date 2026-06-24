"""Print the control -> framework coverage matrix from the taxonomy.

Regenerates the table embedded in the README. Run:
    PYTHONPATH=. python scripts/coverage_matrix.py
"""

from __future__ import annotations

import janreth.security  # noqa: F401  (importing registers every control)
from janreth.security.taxonomy import (
    ASI,
    CONTROLS,
    KC,
    MAESTRO_LAYERS,
    STRIDE,
    TCODES,
    coverage,
)


def _tnum(code: str) -> int:
    return int(code[1:])


def main() -> None:
    print("| Control | Seam | OWASP-Agentic / ASI |")
    print("|---|---|---|")
    for control in sorted(CONTROLS, key=lambda c: c.key):
        codes = ", ".join(list(control.tcodes) + list(control.asi))
        print(f"| **{control.name}** | `{control.seam}` | {codes} |")

    cov = coverage()
    print()
    print(
        f"Coverage: T-codes {len(cov['tcodes'])}/{len(TCODES)} · "
        f"ASI {len(cov['asi'])}/{len(ASI)} · STRIDE {len(cov['stride'])}/{len(STRIDE)} · "
        f"KC {len(cov['kc'])}/{len(KC)} · MAESTRO {len(cov['maestro'])}/{len(MAESTRO_LAYERS)}"
    )
    uncovered = sorted(set(TCODES) - set(cov["tcodes"]), key=_tnum)
    if uncovered:
        print(
            "Not addressed by a runtime control: "
            + ", ".join(f"{t} {TCODES[t]}" for t in uncovered)
        )


if __name__ == "__main__":
    main()
