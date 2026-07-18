// test/liveness.test.js — the mandatory hook-liveness check.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MockOpenClaw } from '../mock_openclaw.js';
import { assertHookEnforces, install } from '../plugin.js';

test('enforcing harness passes liveness', async () => {
  const harness = new MockOpenClaw({ fireHooks: true });
  await assert.doesNotReject(() => assertHookEnforces(harness));
});

test('hook registered but never fired -> liveness FAILS loudly', async () => {
  // Simulates the OpenClaw build where before_tool_call is registered but not
  // called in the exec flow. The PEP must refuse to run, not silently pass.
  const broken = new MockOpenClaw({ fireHooks: false });
  await assert.rejects(
    () => assertHookEnforces(broken),
    /LIVENESS FAILED/
  );
});

test('install refuses to register the gate when liveness fails', async () => {
  const broken = new MockOpenClaw({ fireHooks: false });
  await assert.rejects(
    () => install(broken, { socketPath: '/nonexistent.sock' }),
    /LIVENESS FAILED/
  );
  // No gating handler should have been added beyond the canary attempt.
  assert.equal(broken._handlers.length, 1); // only the liveness canary handler
});
