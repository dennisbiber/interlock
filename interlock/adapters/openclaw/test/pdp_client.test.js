// test/pdp_client.test.js — the fail-closed matrix, hermetic (a tiny JS UDS
// responder stands in for the PDP so these tests need no Python).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { PdpClient, decide, PDP_UNAVAILABLE, SCHEMA_VERSION } from '../pdp_client.js';

function tmpSock() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ilk-')), 'pdp.sock');
}

// Start a UDS responder. `mode` controls the failure being simulated.
function responder(sockPath, handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(sockPath, () => resolve({
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
    }));
  });
}

function verdictResponse(res, verdict) {
  const body = JSON.stringify({ schema_version: SCHEMA_VERSION, verdict });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(body);
}

const CALL = { tool_name: 'delete_email', args: { id: 1 }, session_id: 's', call_id: 'c', effect: null, meta: {} };

test('unreachable socket -> block pdp_unavailable', async () => {
  const client = new PdpClient({ socketPath: '/nonexistent/interlock.sock', timeoutMs: 500 });
  const d = await decide(client, CALL);
  assert.deepEqual(d, { block: true, blockReason: PDP_UNAVAILABLE });
});

test('hung responder -> timeout -> block', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, () => { /* never respond */ });
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 200 });
    const d = await decide(client, CALL);
    assert.deepEqual(d, { block: true, blockReason: PDP_UNAVAILABLE });
  } finally {
    await srv.close();
  }
});

test('malformed response -> block', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => { res.writeHead(200); res.end('not json'); });
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.deepEqual(await decide(client, CALL), { block: true, blockReason: PDP_UNAVAILABLE });
  } finally { await srv.close(); }
});

test('unknown schema_version -> block', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => {
    res.writeHead(200); res.end(JSON.stringify({ schema_version: 999, verdict: { decision: 'allow' } }));
  });
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.deepEqual(await decide(client, CALL), { block: true, blockReason: PDP_UNAVAILABLE });
  } finally { await srv.close(); }
});

test('invalid verdict envelope -> block', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => {
    res.writeHead(200); res.end(JSON.stringify({ schema_version: SCHEMA_VERSION })); // no verdict
  });
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.deepEqual(await decide(client, CALL), { block: true, blockReason: PDP_UNAVAILABLE });
  } finally { await srv.close(); }
});

test('ALLOW -> permit (null)', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => verdictResponse(res, { decision: 'allow', reason: 'ok', grant_id: 'g1' }));
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.equal(await decide(client, CALL), null);
  } finally { await srv.close(); }
});

test('DENY -> block terminal with reason', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => verdictResponse(res, { decision: 'deny', reason: 'rate_limited' }));
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.deepEqual(await decide(client, CALL), { block: true, blockReason: 'rate_limited' });
  } finally { await srv.close(); }
});

test('HOLD -> block with elevation surfaced', async () => {
  const sock = tmpSock();
  const elevation = { capability: 'email:send', scope: { id: 1 }, reason: 'needs approval', call_id: 'c' };
  const srv = await responder(sock, (req, res) => verdictResponse(res, { decision: 'hold', reason: 'held', elevation }));
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    const d = await decide(client, CALL);
    assert.equal(d.block, true);
    assert.match(d.blockReason, /email:send/);
    assert.match(d.blockReason, /re-issue/);
  } finally { await srv.close(); }
});

test('unknown decision -> block (no guessing)', async () => {
  const sock = tmpSock();
  const srv = await responder(sock, (req, res) => verdictResponse(res, { decision: 'sideways' }));
  try {
    const client = new PdpClient({ socketPath: sock, timeoutMs: 500 });
    assert.deepEqual(await decide(client, CALL), { block: true, blockReason: PDP_UNAVAILABLE });
  } finally { await srv.close(); }
});
