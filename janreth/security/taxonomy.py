"""Canonical security taxonomy for Janreth's controls.

Single source of truth mapping each security control to the threat and control
frameworks Janreth maps against:

- OWASP Agentic Threats (T1-T17)
- MAESTRO layers (8)
- OWASP Agentic Top 10 (ASI01-ASI10)
- STRIDE (6)
- OWASP "Securing Agentic Applications" Key Components (KC1-KC6)

Both the README coverage matrix and the attack-suite assertions read from here,
so each control's mapping is declared once and validated against these tables.
Codes and titles are transcribed from the OWASP source packs - no invention.
"""

from __future__ import annotations

from dataclasses import dataclass

# --- Reference code tables (transcribed from the OWASP source packs) ---

TCODES: dict[str, str] = {
    "T1": "Memory Poisoning",
    "T2": "Tool Misuse",
    "T3": "Privilege Compromise",
    "T4": "Resource Overload",
    "T5": "Cascading Hallucination Attacks",
    "T6": "Intent Breaking & Goal Manipulation",
    "T7": "Misaligned & Deceptive Behaviors",
    "T8": "Repudiation & Untraceability",
    "T9": "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human in the Loop",
    "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
    "T16": "Insecure Inter-Agent Protocol Abuse",
    "T17": "Supply Chain Compromise",
}

MAESTRO_LAYERS: tuple[str, ...] = (
    "Foundation Models",
    "Data Operations",
    "Agent Frameworks",
    "Deployment & Infrastructure",
    "Evaluation & Observability",
    "Security & Compliance",
    "Agent Ecosystem",
    "Cross-Layer",
)

ASI: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

STRIDE: tuple[str, ...] = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

# OWASP "Securing Agentic Applications" Key Components.
KC: dict[str, str] = {
    "KC1": "Large Language Models (LLMs)",
    "KC2": "Orchestration (Control Flow)",
    "KC3": "Reasoning / Planning Paradigm",
    "KC4": "Memory Modules",
    "KC5": "Tool Integration Frameworks",
    "KC6": "Operational Environment",
}


@dataclass(frozen=True)
class ControlSpec:
    """A Janreth security control and the frameworks it maps to.

    `seam` names the Agent hook the control attaches to, so the mapping doubles
    as part of the audit trail (which control fired where).
    """

    key: str
    name: str
    summary: str
    seam: str
    tcodes: tuple[str, ...] = ()
    maestro: tuple[str, ...] = ()
    asi: tuple[str, ...] = ()
    stride: tuple[str, ...] = ()
    kc: tuple[str, ...] = ()

    def validate(self) -> None:
        """Raise if any mapped code is absent from the reference tables."""
        for code in self.tcodes:
            if code not in TCODES:
                raise ValueError(f"{self.key}: unknown T-code {code!r}")
        for layer in self.maestro:
            if layer not in MAESTRO_LAYERS:
                raise ValueError(f"{self.key}: unknown MAESTRO layer {layer!r}")
        for code in self.asi:
            if code not in ASI:
                raise ValueError(f"{self.key}: unknown ASI code {code!r}")
        for cat in self.stride:
            if cat not in STRIDE:
                raise ValueError(f"{self.key}: unknown STRIDE category {cat!r}")
        for code in self.kc:
            if code not in KC:
                raise ValueError(f"{self.key}: unknown KC code {code!r}")


# Controls register here as each one is implemented - kept in lock-step with the
# code, and read by the README coverage matrix and the attack-suite assertions.
CONTROLS: list[ControlSpec] = []


def register(spec: ControlSpec) -> ControlSpec:
    """Validate and register a control spec; returns it for assignment."""
    spec.validate()
    if any(c.key == spec.key for c in CONTROLS):
        raise ValueError(f"duplicate control key: {spec.key!r}")
    CONTROLS.append(spec)
    return spec


def coverage() -> dict[str, list[str]]:
    """Framework codes covered by at least one registered control.

    Returns {framework: [covered codes]} - the data behind the README
    control/coverage matrix.
    """
    covered: dict[str, set[str]] = {
        "tcodes": set(),
        "maestro": set(),
        "asi": set(),
        "stride": set(),
        "kc": set(),
    }
    for control in CONTROLS:
        covered["tcodes"].update(control.tcodes)
        covered["maestro"].update(control.maestro)
        covered["asi"].update(control.asi)
        covered["stride"].update(control.stride)
        covered["kc"].update(control.kc)
    return {framework: sorted(codes) for framework, codes in covered.items()}
