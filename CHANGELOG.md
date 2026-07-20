# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-19

First public release. Enforcement is complete and verified end to end against a
real agent harness; the wire protocol and conformance kit are not yet frozen.

### Added

**Core enforcement**
- `GrantLedger` with atomic `find_and_consume`; a single-use grant cannot be
  double-spent (invariant #2).
- `FilterPipeline` with authoritative effect resolution — an adapter-supplied
  effect hint is always discarded and re-resolved from policy (invariant #4).
- `GateKeeper` and `RateLimiter` filters; most-restrictive-wins composition,
  short-circuit on DENY. Rate limiting counts *attempts*, pre-elevation.
- `HumanApprover` and `PolicyApprover` behind an injectable `Channel`. The
  synchronous handshake holds, mints a single-use item-scoped grant on approval,
  and re-runs the chain so the call proceeds in the same evaluation.
- Emergency kill switch, checked before any filter runs.
- Append-only JSONL audit sink; exactly one record per evaluation, covering every
  exit path including the fail-closed ones.

**Service and protocol**
- Single-process PDP daemon over an owner-only Unix domain socket, `0600`
  enforced at startup.
- Frozen wire schema with a top-level `schema_version`. Malformed input, version
  mismatch, and unexpected errors all return a DENY verdict, never a 5xx.

**Adapters**
- `adapters/pdp_client.py` — the shared, harness-agnostic Python PEP core. Fails
  closed on every transport and protocol fault; matches decisions as literal wire
  strings so `pass`/`modify` cannot leak through; blanks any client-supplied
  effect; never short-circuits a call client-side.
- `adapters/hermes/` — Hermes Agent plugin, verified against 0.18.2. Registers in
  a deny-everything posture and arms only after a three-part liveness check
  (source-level wiring audit, canary through the harness's own resolver, induced
  internal fault) proves the hook enforces.
- `adapters/openclaw/` — OpenClaw plugin in JavaScript, Node built-ins only.

**Verification**
- `experiments/hermes-negative-control/` — a containerized three-arm controlled
  experiment against real hermes-agent, with the harness's own approval system
  disabled. Adversarial checks for fail-open, mid-run PDP death, grant
  double-spend, control-arm contamination, reproducibility, and agreement between
  the reported survivor count and actual filesystem state.
- Zero-runtime-dependency CI gate, including a check that dynamic imports are
  declared rather than used to smuggle a dependency past the AST scan.

### Security notes
- The PDP must run as exactly **one process** (invariant #6). Atomic consumption
  rests on an in-process lock; multiple workers will double-spend grants.
- There is **no request authentication in v1**. Access is gated solely by
  filesystem permissions on the socket — put it in an operator-controlled `0700`
  directory.
- Under Hermes, fail-closed depends on the plugin being exception-proof: the
  harness swallows exceptions raised by hooks and then executes the tool. The
  liveness check verifies this on every start.

### Not yet
- `PROTOCOL.md` and a reusable, third-party-runnable conformance kit.
- MODIFY verdicts (the client blocks on them today).
- Cross-process ledger locking.
