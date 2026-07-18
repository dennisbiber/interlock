# Contributing to interlock

Thanks for your interest. interlock is a security component, so contributions
are held to a specific bar — please read this before opening a PR.

## Development setup

No runtime dependencies. For dev tooling (linters/type-checker):

```bash
git clone https://github.com/dennisbiber/interlock
cd interlock
pip install -e ".[dev]"        # ruff + mypy only; runtime stays stdlib-only
```

## Running the tests

The canonical commands (also what CI runs):

```bash
python -m unittest discover -v                       # Python PDP + all unit tests
cd interlock/adapters/openclaw && node --test        # JS PEP (needs Node 20+)
python -m unittest tests.test_e2e_openclaw -v         # cross-language e2e (needs Node)
```

Run `python -m unittest discover` from the **repo root** (tests is a package).

## The invariants are non-negotiable

Any change touching enforcement MUST preserve all five invariants in
[`SECURITY.md`](SECURITY.md). A PR that weakens one will be rejected regardless
of what else it does. If you think an invariant is wrong, open an issue to
discuss it first — don't encode the change in a PR.

## No runtime dependencies

The PDP is stdlib-only and the JS PEP client uses only Node built-ins. This is
enforced in CI (`scripts/check_no_runtime_deps.py`). Dev/test tooling goes in
`[project.optional-dependencies].dev`, never in runtime code.

## Contributing an adapter (PEP)

New harness adapters are welcome and are the main way to grow interlock. An
adapter is accepted only if it:

1. **Reuses the fail-closed core** — it does not reimplement the PDP call /
   verdict handling; the security-critical path stays in one place.
2. **Fails closed on every error path** — unreachable PDP, timeout, partial
   read, unparseable/invalid/unknown-schema response all BLOCK the tool.
3. **Includes a liveness check** that proves the harness hook actually enforces,
   and fails loud (refuses to run) on silent-no-fire.
4. **Maps all verdicts** — ALLOW permits, DENY blocks terminally, HOLD blocks
   with elevation surfaced.
5. **Ships tests** proving 2–4, runnable in CI without a GPU or a paid model.
6. **Adds no runtime dependencies.**

Open an "Adapter proposal" issue first so we can confirm the harness's real
interception point before you build.

## Pull request process

- All PRs are reviewed by the maintainer (see `CODEOWNERS`).
- CI must be green: unit tests, JS tests, e2e, and the zero-dependency check.
- Keep PRs focused; one concern per PR.
- Update docs/tests alongside code.
