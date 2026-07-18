// mock_openclaw.js
//
// ============================ MOCK — NOT OPENCLAW ============================
// A faithful, minimal stand-in for OpenClaw's plugin + tool-execution surface,
// used so the REAL plugin logic can be driven against the REAL Python PDP over a
// REAL unix socket in tests and the demo. It models exactly the contract the
// shim is built to; it is NOT OpenClaw. The thin shim (plugin.js) is what you
// validate against a live OpenClaw install.
// ============================================================================
//
// Modeled contract:
//   - on('before_tool_call', handler): register a handler (priority = order).
//   - registerTool(name, fn): a tool the harness can execute.
//   - executeTool(name, params, ctx): fire handlers in order; the FIRST
//     { block: true } is terminal (remaining handlers skipped) and the tool does
//     NOT run; { params } merges/overrides args and continues; { block:false } or
//     nothing is "no decision" and continues. If nothing blocks, the tool runs.
//   - The `fireHooks:false` mode simulates the broken build where the hook is
//     registered but never called in the exec flow — the liveness check must
//     catch it.

import { randomUUID } from 'node:crypto';

export class MockOpenClaw {
  constructor({ fireHooks = true } = {}) {
    this._handlers = [];
    this._tools = {};
    this._fireHooks = fireHooks;
  }

  on(event, handler) {
    if (event === 'before_tool_call') this._handlers.push(handler);
    return this;
  }

  registerTool(name, fn) {
    this._tools[name] = fn;
    return this;
  }

  async executeTool(toolName, params, ctx = {}) {
    const event = {
      toolName,
      toolCallId: ctx.toolCallId ?? randomUUID(),
      params: params ?? {},
    };
    const fullCtx = {
      sessionKey: ctx.sessionKey,
      runId: ctx.runId,
      callDepth: ctx.callDepth ?? 0,
      parentSpanId: ctx.parentSpanId ?? null,
    };

    if (this._fireHooks) {
      for (const handler of this._handlers) {
        const decision = await handler(event, fullCtx);
        if (decision && decision.block) {
          return { executed: false, blocked: true, blockReason: decision.blockReason };
        }
        if (decision && decision.params) {
          event.params = { ...event.params, ...decision.params };
        }
        // block:false / null / undefined => no decision => continue
      }
    }

    const fn = this._tools[toolName];
    const result = fn ? await fn(event.params) : undefined;
    return { executed: true, blocked: false, result };
  }
}
