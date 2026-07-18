# Security Policy

`interlock` is a security component: a deterministic policy-enforcement layer
that gates agent tool calls. This document is both a disclosure policy and a
threat model, because for a tool like this, being precise about what it does
*not* protect is as important as what it does.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Use GitHub's
private vulnerability reporting: **Security → Report a vulnerability** on this
repository. Include a description, affected version/commit, and a reproduction
if possible. You'll get an acknowledgement, and fixes are coordinated before
public disclosure.

## Supported versions

Pre-1.0: the latest tagged release and `main` receive fixes. Older tags do not.

## What interlock guarantees (the invariants)

1. **Execution-boundary interception.** Enforcement is at the tool-execution
   boundary, never at user input — so autonomous loops, sub-agents, and
   unattended jobs are gated, not just interactive turns.
2. **Atomic single-use consumption.** A grant is spent exactly once; a
   check-then-consume race cannot double-spend it.
3. **Mint is authorizer-only.** Only an `Authorizer` mints grants; the agent and
   the filters cannot. An agent can never grant itself a capability.
4. **Default-deny by effect.** Unclassified tools are treated as consequential
   and gated; a misconfiguration fails safe (over-gated), never open.
5. **PEP fails closed.** If a PEP cannot reach the PDP, times out, or gets an
   unparseable/unknown response, it blocks the tool. Never allow-on-error.

## What interlock does NOT protect against (trust boundaries)

- **In-process code is not sandboxed.** Filters, authorizers, and anything
  running inside the PDP process are trusted. The consume-only view handed to
  filters is defense-in-depth against accidental misuse, **not** a security
  boundary — the real boundary is the process/wire edge. Do not load untrusted
  code into the PDP process.
- **A generic `exec`/shell/`eval` tool is a universal capability.** An agent can
  cause any side effect through it. Such tools MUST be classified consequential
  and gated (or removed), or the fence has a hole.
- **Coverage is only as good as classification.** interlock gates the
  side-effecting tools you classify. Default-deny-by-effect mitigates omissions
  by failing safe, but you still own the effect classification in `policy.json`.
- **Single-writer / single-process.** Atomic consumption relies on an in-process
  lock and in-memory state. Running the PDP under multiple workers/processes
  breaks the guarantee (double-spend, clobbered ledger). Run ONE PDP process.
- **Liveness-path equivalence.** The PEP liveness check proves the hook enforces
  along the path it drives. On a real harness you must ensure that path is the
  same one a model-issued tool call takes; a hook that fires for a canary but not
  for real calls is silent-no-fire. Validate against the live harness.
- **PDP access control is the socket's.** The PDP listens on an owner-only unix
  socket. Any local process running as the socket owner can reach it. It is not
  authenticated beyond filesystem permissions.
- **interlock is not a content scanner.** It is deterministic capability gating,
  not malicious-intent detection. It will faithfully allow a human-approved
  action even if that action is harmful. Pair it with detection if you need it.

## Operator hardening checklist

- Run the PDP as a single process, owner-only socket.
- Classify every side-effecting tool; ensure `exec`/shell tools are consequential.
- Keep grants single-use and short-TTL; protect the operator mint path.
- Validate the PEP liveness check against your actual harness build.
- Keep the PDP process free of untrusted plugins/filters.
