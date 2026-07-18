# interlock — OpenClaw PEP

The Policy Enforcement Point for OpenClaw: a thin JS plugin that gates
`before_tool_call` against the interlock PDP over its unix socket.

## Architecture (core / shim split)

- **`pdp_client.js` — core, harness-agnostic.** The fail-closed UDS client and
  the verdict → decision mapping. No OpenClaw specifics; unit-tested on its own.
- **`plugin.js` — shim, OpenClaw-specific.** Context extraction (`session_id` /
  `call_id` / `effect`), hook registration, and the liveness check. This is the
  only file that moves when OpenClaw's contract shifts.
- **`mock_openclaw.js` — a labeled MOCK** of OpenClaw's exec surface, so the real
  plugin can be driven against the real PDP in tests and the demo. Not OpenClaw.
- **`agent.mjs` / `runaway_demo.py`** — the end-to-end runaway demonstration.

## Fail-closed (invariant #5)

Every one of these BLOCKS the tool — none falls through to allow: socket missing,
connection refused, request timeout, partial read, a response that isn't a valid
verdict envelope, or an unrecognized `schema_version`. Only an explicit `ALLOW`
verdict permits. `DENY` blocks terminally; `HOLD` blocks with the elevation
summary surfaced for out-of-band approval and re-issue (deferred mode). The
client uses a short connect+request timeout so a hung PDP can't hang the agent.
The block reason mirrors the PDP's reserved `pdp_unavailable`.

## Liveness check (mandatory)

Across OpenClaw builds, `before_tool_call` has sometimes been *registered but
never fired* in the exec flow — a PEP that looks installed but isn't in the loop.
`install()` therefore runs `assertHookEnforces()` first: it drives a canary tool
call through the harness and requires the block to take effect. If it can't
confirm enforcement, it throws loudly and registers nothing — never degrade to
"hook registered, hope it fires."

## Identity on the wire

- `session_id`: `ctx.sessionKey` → `ctx.runId` → a UUID generated once per agent
  process. Stable per run — this is what ties a runaway loop to one identity.
- `call_id`: OpenClaw's `event.toolCallId` (correlates PDP audit with OpenClaw's
  own tool record); a UUID only if a path lacks one.
- `effect`: always `null`. The PDP classifies (invariant #4); the PEP never sets it.

## HOLD, today and later

v1 maps `HOLD` → `{ block: true, blockReason: <elevation summary> }` (deferred
mode): the action is blocked now, a human approves out-of-band (an operator mints
a single-use grant), and the agent re-issues, at which point that one grant is
consumed. OpenClaw's native `paused_for_approval` / `resume_token` /
`requireApproval` is a nicer future mapping — noted, not built in v1.

## Wiring into a real OpenClaw install

```js
import { install } from './plugin.js';
// `harness` is your real OpenClaw plugin API (must expose on('before_tool_call'),
// registerTool, and an execution path that honors block:true).
await install(harness, { socketPath: '/run/interlock/interlock.sock', timeoutMs: 2000 });
```

`install` throws if the liveness check fails — treat that as fatal. The canary
tool registered during liveness is inert for real tools; a production binding
should deregister it after the check.

## Tests & demo

```
# JS unit tests (zero deps, Node's built-in runner) — fail-closed matrix + liveness
node --test

# End-to-end (from the repo root): real JS PEP -> real Python PDP -> runaway stopped
python -m unittest tests.test_e2e_openclaw
python interlock/adapters/openclaw/runaway_demo.py
```
