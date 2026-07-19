"""
interlock.service — the PDP daemon (P4).

  ┌─────────────────────────────────────────────────────────────────────────┐
  │ SINGLE PROCESS, SINGLE WRITER — HARD DEPLOYMENT INVARIANT (#6).            │
  │ The grant ledger's atomicity rests on an in-process threading.Lock and an │
  │ in-memory StateStore; the audit and rate-limit state are in-memory too.   │
  │ Under a multi-worker server (gunicorn/uvicorn workers>1, multiple procs)  │
  │ each worker gets its OWN lock and divergent in-memory state and WILL       │
  │ double-spend grants and clobber the save-through file. Run ONE process.   │
  │ Concurrency here is threads within that one process (ThreadingHTTPServer).│
  │ The cross-process path (SQLite BEGIN IMMEDIATE, or a file lock) is a noted│
  │ future option, not built.                                                 │
  └─────────────────────────────────────────────────────────────────────────┘

Transport: a Unix domain socket, owner-only. Off-host by construction, with
filesystem-permission access control. No request auth in v1 is acceptable ONLY
because the socket is bound to the local filesystem and chmod 600 — say so
explicitly. (P5 note: Node's http.request supports `socketPath`, so the JS
OpenClaw PEP connects to this UDS with no obstacle.)

One shared FilterPipeline / GrantLedger / RateLimiter / AuditLog is built at
startup and serves all requests; there is no per-request state. Concurrency
safety rests on the ledger lock and the RateLimiter lock (proven in the tests).

Fail-closed contract: the service answers a well-formed request only with a
Verdict. Malformed/unparseable input -> DENY(malformed_request); an unsupported
schema_version -> DENY(unsupported_schema); any unexpected exception ->
DENY(pdp_error). All of these are HTTP 200 with a DENY verdict — never a 5xx a
PEP might misread, never ALLOW-by-omission.
"""

from __future__ import annotations

import argparse
import contextlib
import http.server
import importlib
import json
import logging
import os
import socket
import socketserver
import stat
import threading

from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.store.session_store import SessionStore
from interlock.audit import JsonlAuditLog
from interlock.authorizers.policy import PolicyApprover
from interlock.types import (
    Verdict,
    Decision,
    MALFORMED_REQUEST_REASON,
    UNSUPPORTED_SCHEMA_REASON,
    PDP_ERROR_REASON,
)
from interlock.wire import (
    SCHEMA_VERSION,
    WireError,
    toolcall_from_wire,
    wrap_response,
)

logger = logging.getLogger("interlock.service")

DEFAULT_MAX_BODY = 64 * 1024  # bytes


class _BodyTooLarge(Exception):
    pass


def _deny(reason: str) -> Verdict:
    return Verdict(Decision.DENY, reason)


# ---------------------------------------------------------------------------
# Core request -> response, independent of transport (so it is unit-testable).
# ---------------------------------------------------------------------------

def respond_for(pdp, raw: bytes) -> dict:
    """
    Map a raw request body to a response envelope. NEVER raises: every failure —
    unparseable body, unsupported schema_version, invalid tool_call, OR an
    exception from pdp.evaluate — becomes a DENY envelope (fail closed). Because
    the evaluate() call is wrapped here rather than in the HTTP handler, invariant
    #5's "never allow by omission" is structural at the transport-independent
    layer, so any future transport (and the P5 adapter) inherits it. The HTTP
    handler keeps its own outer catch as defense-in-depth for read/write errors.
    """
    try:
        msg = json.loads(raw.decode("utf-8"))
    except Exception:
        return wrap_response(_deny(MALFORMED_REQUEST_REASON))
    if not isinstance(msg, dict):
        return wrap_response(_deny(MALFORMED_REQUEST_REASON))
    # Version mismatch fails closed: never parse an unknown future format.
    if msg.get("schema_version") != SCHEMA_VERSION:
        return wrap_response(_deny(UNSUPPORTED_SCHEMA_REASON))
    try:
        call = toolcall_from_wire(msg.get("tool_call"))
    except WireError:
        return wrap_response(_deny(MALFORMED_REQUEST_REASON))
    try:
        verdict = pdp.evaluate(call)
    except Exception:
        logger.exception("pdp.evaluate raised; failing closed")
        return wrap_response(_deny(PDP_ERROR_REASON))
    return wrap_response(verdict)


# ---------------------------------------------------------------------------
# HTTP-over-UDS server
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    timeout = 5  # per-request socket read timeout, so a truncated body can't hang

    def log_message(self, fmt, *args):  # keep the daemon quiet; route to debug
        logger.debug("uds request: " + fmt, *args)

    def do_POST(self):
        try:
            raw = self._read_limited()
            envelope = respond_for(self.server.pdp, raw)
        except _BodyTooLarge:
            envelope = wrap_response(_deny(MALFORMED_REQUEST_REASON))
        except Exception:
            # Outermost catch-all: any unexpected error becomes a DENY, never a
            # crash, a 5xx, or an ambiguous allow.
            logger.exception("interlock handler error")
            envelope = wrap_response(_deny(PDP_ERROR_REASON))
        self._send_json(envelope)

    def _read_limited(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > getattr(self.server, "max_body", DEFAULT_MAX_BODY):
            raise _BodyTooLarge()
        return self.rfile.read(length) if length > 0 else b""

    def _send_json(self, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128  # accept backlog; tolerate bursts of simultaneous connects

    def server_bind(self):
        # Bind the UDS path; skip HTTPServer's INET name/port derivation.
        self.socket.bind(self.server_address)
        self.server_name = "interlock"
        self.server_port = 0


# ---------------------------------------------------------------------------
# Socket lifecycle + permission hardening
# ---------------------------------------------------------------------------

def _safe_unlink(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _reclaim_socket_path(path: str) -> None:
    """Remove a stale socket from a prior crash — but only if nothing is listening."""
    if not os.path.exists(path):
        return
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(path)
    except (ConnectionRefusedError, FileNotFoundError):
        # Nobody is listening: stale socket, safe to remove.
        _safe_unlink(path)
    except OSError as exc:
        # Ambiguous (e.g. path exists but isn't ours): refuse rather than clobber.
        raise RuntimeError(f"cannot reclaim socket path {path!r}: {exc}") from exc
    else:
        raise RuntimeError(f"another interlock service is already listening on {path!r}")
    finally:
        probe.close()


def _verify_owner_only(path: str) -> None:
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise RuntimeError(
            f"refusing to serve: socket {path!r} mode {oct(mode)} is wider than owner-only"
        )


def _warn_if_multiworker() -> None:
    hints = []
    if "gunicorn" in __import__("sys").modules:
        hints.append("gunicorn imported")
    for var in ("WEB_CONCURRENCY", "GUNICORN_CMD_ARGS", "UVICORN_WORKERS"):
        if os.environ.get(var):
            hints.append(var)
    if hints:
        logger.warning(
            "interlock MUST run single-process; detected %s. Multiple workers WILL "
            "double-spend grants and clobber ledger/audit state.", ", ".join(hints)
        )


def make_server(socket_path: str, pdp, max_body: int = DEFAULT_MAX_BODY):
    """Bind an owner-only UDS server for `pdp`. Caller runs/stops it."""
    _reclaim_socket_path(socket_path)
    server = _ThreadingUnixHTTPServer(socket_path, _Handler, bind_and_activate=False)
    old_umask = os.umask(0o177)  # world/group get nothing on the new socket
    try:
        try:
            server.server_bind()
            os.chmod(socket_path, 0o600)          # belt-and-suspenders after umask
            _verify_owner_only(socket_path)        # refuse if somehow wider
            server.server_activate()
        except BaseException:
            server.server_close()
            _safe_unlink(socket_path)
            raise
    finally:
        os.umask(old_umask)
    server.pdp = pdp
    server.max_body = max_body
    return server


def serve(socket_path: str, pdp, max_body: int = DEFAULT_MAX_BODY) -> None:
    _warn_if_multiworker()
    server = make_server(socket_path, pdp, max_body=max_body)
    logger.warning("interlock PDP listening on unix socket %s (SINGLE PROCESS ONLY)", socket_path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _safe_unlink(socket_path)


# ---------------------------------------------------------------------------
# Startup wiring
# ---------------------------------------------------------------------------

def load_callable(spec: str):
    """
    Load a dotted 'module:attr' callable (trusted operator config, same trust
    level as policy.json). Used for the optional PolicyApprover rule.
    """
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(f"rule must be 'module:callable', got {spec!r}")
    # dynamic-import: operator-supplied authorizer path from config, resolved
    # at startup. Not a package dependency; interlock runs without it.
    fn = getattr(importlib.import_module(module_name), attr)
    if not callable(fn):
        raise TypeError(f"{spec!r} is not callable")
    return fn


def build_pipeline(policy_path: str, audit_path: str, state_dir: str,
                   ledger_id: str = "__grants__", rule: str | None = None) -> FilterPipeline:
    """Build the one shared PDP. deferred-HOLD by default; optional PolicyApprover via `rule`."""
    policy = Policy.from_file(policy_path)
    sessions = SessionStore(session_dir=state_dir)
    ledger = GrantLedger(StateStore(), threading.Lock(), sessions=sessions, ledger_id=ledger_id)
    audit = JsonlAuditLog(audit_path)
    authorizer = PolicyApprover(ledger, load_callable(rule)) if rule else None
    filters = [RateLimiter(policy.rate_limit_config()), GateKeeper()]
    return FilterPipeline(filters, ledger, policy, authorizer=authorizer, audit=audit)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser("interlock.service")
    parser.add_argument("--policy", required=True, help="path to policy.json")
    parser.add_argument("--audit", required=True, help="path to the JSONL audit log")
    parser.add_argument("--state-dir", required=True, help="SessionStore dir for the ledger")
    parser.add_argument("--ledger-id", default="__grants__", help="ledger session id")
    parser.add_argument("--socket", required=True, help="unix socket path to bind (owner-only)")
    parser.add_argument("--rule", default=None,
                        help="optional 'module:callable' PolicyApprover rule (trusted config)")
    parser.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    pdp = build_pipeline(args.policy, args.audit, args.state_dir, args.ledger_id, args.rule)
    serve(args.socket, pdp, max_body=args.max_body)


if __name__ == "__main__":
    main()
