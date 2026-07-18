"""P4 service tests — live UDS server, fail-closed contract, concurrency."""

import concurrent.futures
import contextlib
import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import unittest

from interlock.authorizers.policy import PolicyApprover
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall
from interlock import service
from interlock.wire import SCHEMA_VERSION, wrap_request


# Module-level callable for the dotted-path loader / PolicyApprover.
def approve_id_7(req):
    return req.scope.get("id") == 7


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
    "rate_limits": {"key": "session_effect", "default": None, "per_effect": {}},
}


def make_pipeline(authorizer=None):
    ledger = GrantLedger(StateStore(), threading.Lock())
    policy = Policy.from_dict(POLICY)
    filters = [RateLimiter(policy.rate_limit_config()), GateKeeper()]
    pipe = FilterPipeline(filters, ledger, policy, authorizer=authorizer)
    return pipe, ledger


class _UDS(http.client.HTTPConnection):
    """Minimal HTTP client over a unix domain socket."""

    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


@contextlib.contextmanager
def running(pdp, tmp, max_body=service.DEFAULT_MAX_BODY):
    sock_path = os.path.join(tmp, "interlock.sock")
    server = service.make_server(sock_path, pdp, max_body=max_body)
    t = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    t.start()
    try:
        yield sock_path
    finally:
        server.shutdown()
        server.server_close()
        service._safe_unlink(sock_path)


class TransportClosed(Exception):
    """The server closed the connection before the exchange completed.

    This is itself a FAIL-CLOSED outcome: a PEP maps any transport error to
    BLOCK, so nothing executes. It is the expected result when the server
    rejects an oversized body without draining it.
    """


def post(sock_path, envelope=None, raw=None):
    conn = _UDS(sock_path)
    body = raw if raw is not None else json.dumps(envelope)
    try:
        try:
            conn.request("POST", "/evaluate", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            status = resp.status
            data = json.loads(resp.read().decode("utf-8"))
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise TransportClosed() from exc
    finally:
        conn.close()
    return status, data


def call_env(tool="delete_email", args=None, cid="c1", session="s"):
    args = {"id": 1} if args is None else args
    return wrap_request(ToolCall(tool, args, session, cid))


class TestFailClosed(unittest.TestCase):
    def test_malformed_json_denies(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            status, res = post(sock, raw="{not json")
            self.assertEqual(status, 200)
            self.assertEqual(res["verdict"]["decision"], "deny")
            self.assertEqual(res["verdict"]["reason"], "malformed_request")

    def test_bad_tool_call_denies(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            _, res = post(sock, envelope={"schema_version": SCHEMA_VERSION,
                                          "tool_call": {"args": {}}})  # missing fields
            self.assertEqual(res["verdict"]["reason"], "malformed_request")

    def test_version_mismatch_denies(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            env = call_env()
            env["schema_version"] = 999
            _, res = post(sock, envelope=env)
            self.assertEqual(res["verdict"]["decision"], "deny")
            self.assertEqual(res["verdict"]["reason"], "unsupported_schema")

    def test_oversized_body_denies(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d, max_body=1024) as sock:
            big = json.dumps({"schema_version": SCHEMA_VERSION,
                              "tool_call": {"tool_name": "x", "args": {"blob": "a" * 5000},
                                            "session_id": "s", "call_id": "c"}})
            # The server refuses to READ a body over max_body (it must not drain an
            # unbounded body), answers DENY, then closes. Whether the client finishes
            # writing before that close is a RACE -- so both outcomes are valid and
            # both are fail-closed. What must never happen is an ALLOW.
            try:
                _, res = post(sock, raw=big)
            except TransportClosed:
                return  # connection closed under us => nothing executed
            self.assertEqual(res["verdict"]["decision"], "deny")
            self.assertEqual(res["verdict"]["reason"], "malformed_request")

    def test_handler_exception_becomes_pdp_error(self):
        class BoomPipe:
            def evaluate(self, call):
                raise RuntimeError("boom")

        with tempfile.TemporaryDirectory() as d, running(BoomPipe(), d) as sock:
            with self.assertLogs("interlock.service", level="ERROR"):
                status, res = post(sock, envelope=call_env("list_inbox", {}))
            self.assertEqual(status, 200)  # never a 5xx
            self.assertEqual(res["verdict"]["decision"], "deny")
            self.assertEqual(res["verdict"]["reason"], "pdp_error")

    def test_respond_for_catches_evaluate_error(self):
        # Fail-closed is structural at the transport-independent layer, not only
        # in the HTTP handler.
        class BoomPipe:
            def evaluate(self, call):
                raise RuntimeError("boom")

        env = wrap_request(ToolCall("list_inbox", {}, "s", "c"))
        with self.assertLogs("interlock.service", level="ERROR"):
            res = service.respond_for(BoomPipe(), json.dumps(env).encode("utf-8"))
        self.assertEqual(res["verdict"]["decision"], "deny")
        self.assertEqual(res["verdict"]["reason"], "pdp_error")


class TestVerdicts(unittest.TestCase):
    def test_passive_allows(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            _, res = post(sock, envelope=call_env("list_inbox", {}))
            self.assertEqual(res["verdict"]["decision"], "allow")

    def test_deferred_hold_returned_on_wire(self):
        pipe, _ = make_pipeline(authorizer=None)  # deferred mode
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            _, res = post(sock, envelope=call_env("delete_email", {"id": 1}))
            v = res["verdict"]
            self.assertEqual(v["decision"], "hold")
            self.assertEqual(v["elevation"]["capability"], "email:send")
            self.assertEqual(v["elevation"]["scope"], {"id": 1})
            self.assertEqual(v["elevation"]["call_id"], "c1")

    def test_policy_approver_auto_approves_through_live_service(self):
        pipe, ledger = make_pipeline()
        pipe._authorizer = PolicyApprover(ledger, approve_id_7)  # synchronous path
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            _, ok = post(sock, envelope=call_env("delete_email", {"id": 7}, cid="a"))
            self.assertEqual(ok["verdict"]["decision"], "allow")
            _, no = post(sock, envelope=call_env("delete_email", {"id": 8}, cid="b"))
            self.assertEqual(no["verdict"]["decision"], "deny")


class TestSocketHardening(unittest.TestCase):
    def test_socket_is_owner_only(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            mode = stat.S_IMODE(os.stat(sock).st_mode)
            self.assertEqual(mode & 0o077, 0)  # no group/other bits

    def test_stale_socket_is_reclaimed(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d:
            sock_path = os.path.join(d, "interlock.sock")
            # Leave a stale socket file (bound, never listened, then closed).
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(sock_path)
            stale.close()
            self.assertTrue(os.path.exists(sock_path))
            server = service.make_server(sock_path, pipe)  # must reclaim, not fail
            server.server_close()
            service._safe_unlink(sock_path)

    def test_live_socket_is_not_clobbered(self):
        pipe, _ = make_pipeline()
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            with self.assertRaises(RuntimeError):
                service.make_server(sock, pipe)  # second bind on a live socket refuses


class TestLoadCallable(unittest.TestCase):
    def test_dotted_path_loads(self):
        fn = service.load_callable("tests.test_service:approve_id_7")
        self.assertEqual(fn.__qualname__, "approve_id_7")
        # Assert on behavior, not object identity (robust to how discovery imports).
        from interlock.types import ElevationRequest
        yes = ElevationRequest(ToolCall("delete_email", {"id": 7}, "s", "c"), "email:send", {"id": 7}, "r")
        no = ElevationRequest(ToolCall("delete_email", {"id": 8}, "s", "c"), "email:send", {"id": 8}, "r")
        self.assertTrue(fn(yes))
        self.assertFalse(fn(no))

    def test_bad_spec_raises(self):
        with self.assertRaises(ValueError):
            service.load_callable("no_colon_here")


class TestLiveConcurrency(unittest.TestCase):
    def test_many_requests_one_grant_exactly_one_allow(self):
        # Many simultaneous requests over the REAL socket contend for one
        # single-use grant. The ledger + RateLimiter locks must hold across the
        # threaded server: exactly one ALLOW, the rest HOLD (deferred mode).
        pipe, ledger = make_pipeline(authorizer=None)
        ledger.mint("email:send", {"id": 1}, uses=1, ttl=None, granted_by="dennis")

        n = 40
        with tempfile.TemporaryDirectory() as d, running(pipe, d) as sock:
            barrier = threading.Barrier(n)

            def worker(i):
                barrier.wait()
                _, res = post(sock, envelope=call_env("delete_email", {"id": 1}, cid=f"c{i}"))
                return res["verdict"]["decision"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
                decisions = [f.result() for f in [ex.submit(worker, i) for i in range(n)]]

        self.assertEqual(sum(x == "allow" for x in decisions), 1)
        self.assertEqual(sum(x == "hold" for x in decisions), n - 1)


if __name__ == "__main__":
    unittest.main()