# interlock — Hermes Agent adapter

A `pre_tool_call` plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that routes every tool call through the interlock PDP. Nothing consequential
executes without an unforgeable, single-use, item-scoped grant.

Verified against **hermes-agent 0.18.2** by reading its installed source.

---

## Install

```bash
pip install hermes-agent          # your harness
pip install interlock             # this project

mkdir -p ~/.hermes/plugins/interlock
cp -r $(python -c 'import interlock.adapters.hermes as m, os; print(os.path.dirname(m.__file__))')/* \
      ~/.hermes/plugins/interlock/

export INTERLOCK_SOCKET=/run/interlock/interlock.sock
python -m interlock.service --socket "$INTERLOCK_SOCKET" --policy policy.json &
hermes
```

| Variable | Meaning |
|---|---|
| `INTERLOCK_SOCKET` | **Required.** Path to the PDP's unix socket. Unset ⇒ every tool call is denied. |
| `INTERLOCK_TIMEOUT` | PDP round-trip deadline in seconds. Default `2.0`. |
| `INTERLOCK_EXIT_ON_LIVENESS_FAILURE` | `1` ⇒ hard-exit instead of running in deny-everything mode. Recommended for unattended deployments. |

On a healthy start you'll see:

```
interlock: enforcement ARMED for Hermes (socket=/run/interlock/interlock.sock).
liveness: wiring=ok enforce=ok fault=ok (3/3 dispatch modules call resolve_pre_tool_block)
```

If you don't see `ARMED`, interlock is denying every tool call. That is the
intended failure mode, not a bug.

---

## What you should know before trusting this

This section exists because a security tool that oversells itself is worse than
none. These are properties of **Hermes**, not of interlock, and interlock works
around each one — but you should know they're there.

### Hermes swallows exceptions raised by plugin hooks, then runs the tool

`PluginManager.invoke_hook` wraps each callback in `try/except`, logs a warning,
and continues. A callback that raises contributes no directive, so
`resolve_pre_tool_block` returns `None` and **the tool executes**. There is also
a swallowing handler at the `model_tools.py` dispatch site.

**In this harness, an exception escaping the hook is an ALLOW.**

Interlock's callback therefore catches `Exception` at its outermost level and
converts anything unexpected into a block. This means fail-closed under Hermes
is a property of *interlock's code being exception-proof*, not a property the
harness guarantees. The liveness check verifies it on every start by
deliberately inducing an internal fault and requiring a block anyway — but if
you fork this adapter, that outermost handler is not optional.

### A block directive with an empty message is discarded

`_get_pre_tool_call_directive_details` skips a `block` whose message is falsy.
An empty message is an allow. Every block interlock emits is guaranteed
non-empty.

### Registering a hook proves nothing

`PluginContext.register_hook` warns on an unknown hook name and **stores it
anyway** for forward compatibility. A one-character typo registers
"successfully", never fires, and reports no error. Separately, a harness build
whose dispatch path doesn't call the gate would leave a correctly-registered
hook that never runs.

This is why the adapter never treats successful registration as evidence. See
*Liveness* below.

### Raising from `register()` is worse than useless

`PluginManager._load_plugin` wraps `register(ctx)` in `except Exception` and logs
a warning. A plugin that raises to protest a misconfiguration is a plugin whose
hook was **never registered**, in an agent that starts anyway and runs
completely ungated.

So this adapter inverts the usual order: it **registers the hook first, in a
deny-everything posture**, and only arms normal enforcement once liveness
passes. Every failure mode then leaves an agent that refuses to act — loud and
safe — rather than one that acts freely while appearing guarded.

---

## Liveness

Runs on every start, against the installed Hermes. Three independent checks:

| Check | Question | Catches |
|---|---|---|
| **wiring** | Do the dispatch modules actually call `resolve_pre_tool_block`? | A build where the hook runner exists but nothing calls it |
| **enforce** | Does driving a canary through Hermes's own resolver return *our* block message? | Typo'd hook names, unregistered callbacks, directives not honored, another plugin blocking and being mistaken for us |
| **fault** | Does an internal hook error still produce a block? | The swallowed-exception allow path above |

All three must pass or the plugin stays in deny-everything mode.

**The honest limit.** The enforce and fault probes drive
`hermes_cli.plugins.resolve_pre_tool_block`, the single entry point all four
tool-dispatch sites call. The wiring check is what connects that function to the
dispatch sites, by reading the installed source. Together that's strong
evidence — but it is not the same as a model issuing a real tool call. A build
reaching tool execution by a fifth path this check doesn't know about would not
be caught. If you find one, add it to `DISPATCH_MODULES` in `liveness.py`.

---

## Design notes

**The PDP classifies, not the adapter.** `effect` is always `None` on the way
out. A shim cannot talk a consequential tool into the passive lane.

**No client-side short-circuit.** Every tool call makes the round trip,
including obviously-passive ones, because the PDP is the authority on effect
classification. A local UDS round trip is sub-millisecond; a client-side
classification cache would be a second policy engine with no audit trail.

**Hermes's `approve` directive is deliberately unused.** `pre_tool_call` can
return `{"action": "approve"}` to route through Hermes's own human-approval
gate. Interlock does not use it: that gate cannot mint an interlock grant, so
you'd get a dual-approval where Hermes says yes and interlock still holds.
`hold` blocks terminally and requires an out-of-band mint, which keeps the
enforcement path model-free and harness-independent. A possible future opt-in
mode, not v1.

**Version gating is on behavior, not version strings.** An unverified
hermes-agent version logs a warning and proceeds. Version strings lie and
pinning creates false confidence; the liveness check is the real gate.

**The whole harness mapping is three lines** (`from_outcome` in `plugin.py`):
`None` to permit, `{"action": "block", "message": reason}` otherwise. That
smallness is the evidence the core/shim seam is in the right place — every
security-critical decision lives in `interlock/adapters/pdp_client.py`, shared
with every other Python harness.

---

## Verified behavior

Against real hermes-agent 0.18.2 with a real PDP over a real unix socket:

```
LIVENESS: wiring=ok enforce=ok fault=ok (3/3 dispatch modules call resolve_pre_tool_block)

RUNAWAY: 50 autonomous delete_file calls, 1 operator approval
  survivors (blocked): 49/50
  executed           : [7]
  passive list_files : ALLOW
  PDP killed -> next call: BLOCK
```

One approval, one execution, forty-nine survivors — and killing the PDP
mid-run blocks everything rather than opening the gate.
