// plugin.js — the OpenClaw-specific SHIM (thin, so it moves alone when the
// OpenClaw contract shifts).
//
// Responsibilities kept here and NOWHERE else:
//   - context extraction: session_id / call_id / effect from the event+ctx
//   - hook registration onto OpenClaw's before_tool_call
//   - the MANDATORY liveness check (prove the hook actually enforces)
//
// OpenClaw contract this is built to:
//   - before_tool_call fires before tool.execute(); returning { block: true,
//     blockReason } is TERMINAL and prevents execution; { params } merges args;
//     { block: false } or nothing is "no decision" (NOT an allow-override).
//   - event = { toolName, toolCallId, params }; ctx exposes sessionKey, runId,
//     callDepth, parentSpanId; handlers may be async.

import { randomUUID } from 'node:crypto';
import { PdpClient, decide } from './pdp_client.js';

const CANARY_TOOL = '__interlock_canary__';

// --- context extraction ----------------------------------------------------

let _procSession = null;
function processSessionId() {
  if (!_procSession) _procSession = 'agent:' + randomUUID();
  return _procSession;
}

// STABLE per-run identity: sessionKey -> runId -> one-per-process UUID. This is
// what ties a runaway loop to one identity for rate-limiting and audit.
export function sessionIdFrom(ctx = {}) {
  return ctx.sessionKey ?? ctx.runId ?? processSessionId();
}

export function toToolCall(event, ctx = {}) {
  return {
    tool_name: event.toolName,
    args: event.params ?? {},
    session_id: sessionIdFrom(ctx),
    // OpenClaw's own tool id, so PDP audit correlates with OpenClaw's record.
    call_id: event.toolCallId ?? randomUUID(),
    effect: null, // never trust the JS side; PDP classifies (invariant #4)
    meta: {},
  };
}

export function makeBeforeToolCall(client) {
  return async function beforeToolCall(event, ctx) {
    return await decide(client, toToolCall(event, ctx));
  };
}

// --- liveness check (mandatory) --------------------------------------------

// PROVE the hook is in the execution path before trusting it. Across OpenClaw
// builds the hook has been registered but never actually fired (silent no-fire)
// — a PEP that looks installed but isn't in the loop is the single worst failure
// here. We drive a canary through the harness and require the block to take
// effect; otherwise we FAIL LOUD rather than degrade to "hope it fires".
export async function assertHookEnforces(harness) {
  let canaryExecuted = false;
  harness.registerTool(CANARY_TOOL, async () => { canaryExecuted = true; });
  harness.on('before_tool_call', async (event) => {
    if (event.toolName === CANARY_TOOL) return { block: true, blockReason: 'interlock-liveness' };
    return null; // abstain for every real tool
  });

  const outcome = await harness.executeTool(CANARY_TOOL, {}, { sessionKey: 'liveness' });

  if (canaryExecuted || (outcome && outcome.executed)) {
    throw new Error(
      'interlock LIVENESS FAILED: before_tool_call did not block a canary tool call. ' +
      'The hook is NOT enforcing in this OpenClaw build — refusing to run unguarded ' +
      '(every tool call would sail through while appearing protected).'
    );
  }
}

// --- install ---------------------------------------------------------------

// Run liveness first (throws loudly on failure), THEN register the real gating
// handler. Returns the PdpClient. If liveness throws, nothing is registered and
// the caller must not proceed.
export async function install(harness, { socketPath, timeoutMs = 2000 } = {}) {
  await assertHookEnforces(harness);
  const client = new PdpClient({ socketPath, timeoutMs });
  harness.on('before_tool_call', makeBeforeToolCall(client));
  return client;
}
