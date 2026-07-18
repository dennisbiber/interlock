// pdp_client.js — the harness-agnostic PEP core.
//
// Fail-closed is the whole point (invariant #5). Every failure mode BLOCKS the
// tool; none may fall through to allow:
//   socket missing / connection refused / timeout / partial read /
//   response that isn't a valid verdict envelope / unrecognized schema_version.
// Only an explicit ALLOW verdict permits. DENY blocks terminally; HOLD blocks
// with the elevation summary surfaced (deferred mode — a human approves
// out-of-band and the agent re-issues).
//
// This module is transport/harness-agnostic and has NO OpenClaw specifics, so
// it can be unit-tested on its own and reused if OpenClaw's contract shifts.

import http from 'node:http';

export const SCHEMA_VERSION = 1;
export const PDP_UNAVAILABLE = 'pdp_unavailable'; // mirrors the Python reserved reason

export class PdpUnavailable extends Error {}

export class PdpClient {
  constructor({ socketPath, timeoutMs = 2000 } = {}) {
    this.socketPath = socketPath;
    this.timeoutMs = timeoutMs;
  }

  // Returns a wire verdict object { decision, reason, ... } or throws PdpUnavailable.
  async evaluate(toolCall) {
    const body = JSON.stringify({ schema_version: SCHEMA_VERSION, tool_call: toolCall });
    const raw = await this._post(body); // throws PdpUnavailable on any transport error/timeout

    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      throw new PdpUnavailable('unparseable response');
    }
    if (!msg || typeof msg !== 'object') throw new PdpUnavailable('non-object response');
    if (msg.schema_version !== SCHEMA_VERSION) throw new PdpUnavailable('unrecognized schema_version');
    const v = msg.verdict;
    if (!v || typeof v !== 'object' || typeof v.decision !== 'string') {
      throw new PdpUnavailable('invalid verdict envelope');
    }
    return v;
  }

  _post(body) {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          socketPath: this.socketPath,
          path: '/evaluate',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
          timeout: this.timeoutMs, // short: a hung PDP must not hang the agent
        },
        (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (c) => { data += c; });
          res.on('end', () => resolve(data));
          res.on('aborted', () => reject(new PdpUnavailable('partial read (aborted)')));
          res.on('error', () => reject(new PdpUnavailable('response stream error')));
        }
      );
      req.on('timeout', () => { req.destroy(new PdpUnavailable('timeout')); });
      req.on('error', (e) =>
        reject(e instanceof PdpUnavailable ? e : new PdpUnavailable(`transport: ${e.code || e.message}`))
      );
      req.write(body);
      req.end();
    });
  }
}

// Map a verdict (or a failure) to an OpenClaw before_tool_call return value.
//   permit  -> null            (return nothing to the harness)
//   block   -> { block: true, blockReason }
//   modify  -> { params }      (MODIFY deferred in v1; documented no-op path)
export async function decide(client, toolCall) {
  let verdict;
  try {
    verdict = await client.evaluate(toolCall);
  } catch {
    // ANY transport/parse/timeout error fails closed.
    return { block: true, blockReason: PDP_UNAVAILABLE };
  }

  switch (verdict.decision) {
    case 'allow':
      // Only an explicit ALLOW permits. MODIFY is deferred in v1; if the PDP
      // ever sends modified_args, pass them through (documented no-op for now).
      if (verdict.modified_args) return { params: verdict.modified_args };
      return null; // permit
    case 'deny':
      return { block: true, blockReason: verdict.reason || 'denied' };
    case 'hold':
      return { block: true, blockReason: holdSummary(verdict) };
    default:
      // Unknown decision string -> fail closed, don't guess.
      return { block: true, blockReason: PDP_UNAVAILABLE };
  }
}

export function holdSummary(verdict) {
  const e = verdict.elevation;
  if (!e) return 'held: requires approval';
  const scope = (() => { try { return JSON.stringify(e.scope); } catch { return String(e.scope); } })();
  return `held: requires approval for ${e.capability} on ${scope} (call ${e.call_id}). ` +
         `An operator must approve out-of-band; the agent then re-issues.`;
}
