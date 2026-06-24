# Teardown — Janreth assessed by the Janreth GCC Platform

The proof-first launch artifact: run this framework through the Janreth GCC
Platform (the agentic-AI threat-modeling product) and show, side by side, that
the threats an independent assessment flags are the ones Janreth's controls and
attack suite already cover.

## Run it

1. Start the GCC Platform (API + worker + Redis; a provider key set). See that
   repo's README.
2. `POST /generate` with the prose in `architecture.md`, **controls-off variant**
   → the raw agentic-threat surface (T-codes, ASI, MAESTRO layers, obligations).
3. `POST /generate` again with the **controls-on variant** appended → the
   residual surface after Janreth's defenses.
4. Export each report (`GET /generated/{id}?format=pdf`).
5. Run `python -m attacks > attacks.json` here for the corroborating proof that
   each control blocks its attack.

## Cross-reference

Put the platform's flagged T-codes/ASI next to `janreth/security/taxonomy.py`
(or the README coverage matrix). The claim, stated plainly:

> The threats an independent agentic-threat assessment flags are the ones
> Janreth's controls cover — and the attack suite proves each control blocks the
> matching attack.

Note the honest gaps from the README ("What this does NOT protect against"):
T7 and T14 have no runtime control, and the detectors are advisory heuristics.
Platform fine/impact figures are advisory estimates — verify with counsel.

## Output

Assemble here: the two report PDFs, `attacks.json`, and a one-page side-by-side
matrix. That package is the blog/LinkedIn launch piece and a live demo of the
GCC Platform.

> Not yet run — this needs the live platform + a provider key. The inputs and the
> procedure are ready.
