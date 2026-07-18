// agent.mjs — a mock autonomous OpenClaw agent used by the demo and the Python
// e2e orchestrator. It installs the REAL plugin (with the liveness check) onto
// the MOCK harness, points it at a REAL PDP unix socket, and attempts to delete
// each --items id, emitting one JSON line per attempt:
//   { "item": 1, "outcome": "allow"|"block", "reason": <string|null> }
//
// Usage:
//   node agent.mjs --socket /path/i.sock --session s --items 1,2,3 [--timeout 2000]

import { parseArgs } from 'node:util';
import { MockOpenClaw } from './mock_openclaw.js';
import { install } from './plugin.js';

const { values } = parseArgs({
  options: {
    socket: { type: 'string' },
    session: { type: 'string' },
    items: { type: 'string' },
    timeout: { type: 'string' },
  },
});

const harness = new MockOpenClaw({ fireHooks: true });

// The consequential tool. Records real executions so we can see the runaway stop.
const deleted = [];
harness.registerTool('delete_email', async (params) => {
  deleted.push(params.id);
  return { deleted: params.id };
});

let client;
try {
  client = await install(harness, {
    socketPath: values.socket,
    timeoutMs: Number(values.timeout ?? 2000),
  });
} catch (e) {
  // Liveness failure is fatal and loud — never proceed unguarded.
  console.log(JSON.stringify({ fatal: 'liveness', error: String(e.message || e) }));
  process.exit(3);
}

const items = (values.items ?? '').split(',').filter(Boolean).map(Number);
for (const id of items) {
  const outcome = await harness.executeTool(
    'delete_email',
    { id },
    { sessionKey: values.session, toolCallId: `tc-${id}-${Math.random().toString(36).slice(2, 8)}` }
  );
  console.log(JSON.stringify({
    item: id,
    outcome: outcome.blocked ? 'block' : 'allow',
    reason: outcome.blockReason ?? null,
  }));
}
