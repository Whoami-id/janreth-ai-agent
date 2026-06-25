"""The ASI mappings must match the authoritative OWASP T->ASI crosswalk.

ASI is derived from a control's T-codes, never hand-assigned - this pins the
crosswalk to its known-good values so a transcription error fails the build.
"""

from __future__ import annotations

import janreth.security  # noqa: F401  (registers every control)
from janreth.security.taxonomy import ASI, CONTROLS, TCODE_TO_ASI, TCODES, asi_for


def _asi_to_tcodes() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for tcode, asis in TCODE_TO_ASI.items():
        for asi_code in asis:
            out.setdefault(asi_code, set()).add(tcode)
    return out


def test_crosswalk_pins_known_asi():
    # The two the OWASP reference (and the GCC platform packs) specify.
    a2t = _asi_to_tcodes()
    assert a2t["ASI01"] == {"T6", "T7"}
    assert a2t["ASI09"] == {"T7", "T8", "T10"}


def test_crosswalk_is_complete_and_valid():
    assert set(TCODE_TO_ASI) == set(TCODES)  # every T-code is mapped
    for tcode, asis in TCODE_TO_ASI.items():
        for asi_code in asis:
            assert asi_code in ASI  # only valid ASI codes appear


def test_control_asi_is_derived_not_invented():
    # A control's ASI is exactly what the crosswalk derives from its T-codes.
    for control in CONTROLS:
        assert set(control.asi) == set(asi_for(control.tcodes)), control.key
