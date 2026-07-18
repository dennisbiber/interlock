## What & why

<!-- What does this change and why. Link any related issue. -->

## Invariant checklist (required)

This project is a security component. Confirm each, or explain why it doesn't apply:

- [ ] Enforcement stays at the **tool-execution boundary**, not user input.
- [ ] Single-use grant consumption remains **atomic** (no check-then-consume race).
- [ ] `mint()` remains reachable **only** from an `Authorizer`.
- [ ] Default posture remains **deny-by-effect**; unclassified tools stay consequential.
- [ ] Any PEP touched **fails closed** on PDP unavailability/timeout/bad response.

## Quality gates

- [ ] `python -m unittest discover` passes locally.
- [ ] `node --test` passes (if JS touched).
- [ ] No new runtime dependencies (`python scripts/check_no_runtime_deps.py`).
- [ ] Tests added/updated for the change.
- [ ] Docs updated (README / SECURITY / relevant guide) if behavior changed.

## Adapter PRs only

- [ ] Reuses the fail-closed core (no reimplementation of the PDP call).
- [ ] Includes a liveness check that fails loud on silent-no-fire.
- [ ] Maps all four verdicts (ALLOW/DENY/HOLD/MODIFY).
