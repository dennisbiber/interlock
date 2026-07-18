# interlock

A passive **policy-enforcement layer** for agent tool calls — one enforcement
brain (a PDP), thin per-harness enforcement points (PEPs), sudo-for-agents.

Interception happens at the **tool-execution boundary, never at user input**, so
`interlock` gates autonomous loops, spawned sub-agents, and unattended jobs — not
just interactive requests. A runaway agent that decides to delete 200 emails hits
the gate 200 times; a single-use, human-approved grant is spent on the first
delete, and the rest hold again.

## Load-bearing invariants

1. Interception is at the tool-execution boundary, never at user input.
2. `find_and_consume` is atomic — a single-use grant can never be double-spent.
3. `mint()` is reachable only from an `Authorizer` (by construction). The consume-only
   view handed to filters is defense-in-depth, not a boundary; the real boundary is the
   process/wire edge.
4. Default posture is deny, classified by effect; unclassified tools are consequential.
5. The PEP fails **closed** on PDP unavailability (timeout/error → block, never allow).
6. The PDP runs as a **single process**. Atomic consumption rests on an in-process lock;
   multi-processing the ledger voids invariant #2 until the lock is replaced by a
   cross-process mechanism. This binds the P4 service design.

## Layout

```
interlock/
├── types.py        # P0 — ToolCall, Verdict, Decision, FilterResult, Grant, ElevationRequest
├── store/          #      vendored StateStore / SessionStore (public APIs unchanged)
├── ledger.py       # P0 — GrantLedger (atomic find_and_consume, mint, revoke, all)
├── pipeline.py     # P1 — FilterPipeline (+ P2 handshake/kill-check, P3 audit funnel)
├── filters/        # P1/P3 — Filter protocol, GateKeeper, RateLimiter
├── authorizers/    # P2 — Authorizer/Channel protocols, HumanApprover, PolicyApprover
├── audit.py        # P3 — append-only JSONL audit sink (AuditSink protocol)
├── wire.py         # P4 — frozen wire schema (single (de)serialization chokepoint)
├── service.py      # P4 — loopback PDP daemon (Unix domain socket, single process)
└── adapters/       # P5 — HarnessAdapter protocol (Python) + OpenClaw PEP (JS)
```

Built in phases P0..P5, one phase at a time.

- **P0 — core types + ledger.** Complete. Atomic `find_and_consume`, single-use grants, durability.
- **P1 — pipeline + Filter protocol + GateKeeper.** Complete. Authoritative effect
  resolution (invariant #4), most-restrictive-wins composition with short-circuit on
  DENY, consume-only ledger view for filters (invariant #3). Config in `policy.json`.
- **P2 — Authorizer + handshake.** Complete. `HumanApprover` (behind an injectable
  `Channel`) and `PolicyApprover` (deterministic no-human rule), both minting single-use
  grants; synchronous HOLD → approve → mint → re-issue → ALLOW handshake (deferred mode
  when no authorizer is wired); emergency kill switch checked first in `evaluate()`;
  construction-time check that consuming filters run last.
- **P3 — AuditLog + RateLimiter.** Complete. Append-only JSONL audit sink (write-failure
  safe, one record per `evaluate()` via a single `_finish` funnel covering every exit
  path). Fixed-window, thread-safe (per-instance lock) `RateLimiter` keyed
  per-`(session, effect)`, skipping passive effects, `call_id`-deduped across the
  handshake re-run; it counts **attempts** per window (not approved actions — it runs
  before elevation), per-effect limits are hard ceilings (cap even human-approved),
  default `null` (opt-in). Rate-limit denials carry the reserved reason `rate_limited`.
- **P4 — PDP service.** Complete. One-process, thread-concurrent daemon over an
  owner-only Unix domain socket; one shared pipeline serves all requests. Frozen wire
  schema (`wire.py`) with top-level `schema_version`; fail-closed on malformed input,
  version mismatch, and unexpected error (all HTTP 200 + DENY, never 5xx). Deferred-HOLD
  by default; optional `PolicyApprover` via a dotted-path rule.
- **P5 — OpenClaw PEP + demo.** Complete. Python `HarnessAdapter` protocol plus a JS
  OpenClaw plugin (`adapters/openclaw/`): a harness-agnostic fail-closed UDS client +
  verdict mapping, a thin OpenClaw shim, and a **mandatory hook-liveness check** that
  refuses to run if `before_tool_call` doesn't actually enforce. The PEP fails closed on
  every unreachable/timeout/malformed/unknown-schema path (invariant #5). The end-to-end
  demo reproduces the §9 runaway: many autonomous deletes, one approval, exactly one
  delete succeeds, the rest blocked.

## Running the service

```
python -m interlock.service \
  --policy policy.json --audit audit.jsonl --state-dir ./state \
  --socket /run/interlock/interlock.sock \
  [--rule my_rules:auto_approve] [--ledger-id __grants__]
```

The service binds a **Unix domain socket**, chmod `0600` (owner-only), verified at
startup and refused if wider. It is off-host by construction; there is **no request
auth in v1, which is acceptable only because access is gated by filesystem
permissions on the socket** — put the socket in an operator-controlled `0700`
directory. A stale socket from a prior crash is reclaimed only if nothing is
listening; a live socket is never clobbered.

> **SINGLE PROCESS, SINGLE WRITER (invariant #6).** Run exactly one process. The
> ledger lock, in-memory store, audit, and rate-limit state are per-process; multiple
> workers (gunicorn/uvicorn `workers>1`, multiple procs) **will** double-spend grants
> and clobber each other's state. Concurrency is threads within one process. The
> cross-process path (SQLite `BEGIN IMMEDIATE` / file lock) is a future option, not
> built.

*P5 note:* Node's `http.request` supports `socketPath`, so the JS OpenClaw PEP connects
to this UDS with no extra machinery.

## Tests

Zero third-party dependencies; standard-library `unittest`. Canonical command,
run from the repo root:

```
python -m unittest discover -s tests -t .
```

The OpenClaw PEP has its own zero-dependency JS tests (Node's built-in runner):

```
cd interlock/adapters/openclaw && node --test
```

See `interlock/adapters/openclaw/README.md` and the end-to-end runaway demo
(`python interlock/adapters/openclaw/runaway_demo.py`).

## Provenance

`store/state_store.py` and `store/session_store.py` are vendored verbatim from
`LMContextCompiler` with public APIs unchanged; the only edit is retargeting
`session_store.py`'s internal import to this package.
