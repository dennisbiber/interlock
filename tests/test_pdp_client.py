"""
The fail-closed battery for the shared Python PEP core (H0.1).

This is the conformance kit's core in substance: cases 1-9 and 12 of the kit
described in the adapter handoff, plus the induced-fault case that H1's liveness
check will drive through a real harness. Cases 10 and 11 (liveness proves the
hook enforces / fails loud on silent-no-fire) are adapter-specific and live with
the adapter that implements them. Formalizing this file into a reusable,
parameterized kit is deferred; the assertions are the deliverable.

Two kinds of test here, and the split is intentional:

  * against a FAKE responder — a raw UDS listener that can produce responses a
    correct PDP never would (truncated, oversized, wrong status, wrong schema,
    impossible decision strings). This is where fail-closed is actually proven,
    because the real service is too well behaved to exercise these paths.

  * against the REAL service and a REAL pipeline over a REAL socket, for the
    three verdicts that matter and for invariant #4.
"""

import json
import os
import socket
import tempfile
import threading
import unittest

from interlock import service
from interlock.adapters.pdp_client import (
    PdpClient,
    PdpUnavailable,
    PepOutcome,
    decide,
)
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import PDP_UNAVAILABLE_REASON, ToolCall
from interlock.wire import SCHEMA_VERSION

POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:delete", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},  # deferred HOLD, no auto-approve
    "rate_limits": {"key": "session_effect", "default": None, "per_effect": {}},
}


def call(tool="delete_email", args=None, session="s1", call_id="c1", effect=None):
    return ToolCall(
        tool_name=tool,
        args={"id": 1} if args is None else args,
        session_id=session,
        call_id=call_id,
        effect=effect,
    )


def http_response(body: bytes, status: str = "200 OK", content_length=None) -> bytes:
    """Build a raw HTTP/1.1 response. content_length may deliberately lie."""
    length = len(body) if content_length is None else content_length
    head = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {length}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    return head + body


def envelope(verdict: dict, schema_version=SCHEMA_VERSION) -> bytes:
    return json.dumps({"schema_version": schema_version, "verdict": verdict}).encode("utf-8")


class FakeResponder:
    """
    A raw AF_UNIX listener that hands each connection to `handler(conn)`.

    Deliberately NOT built on http.server: several cases require responses that
    a well-formed HTTP server cannot emit.
    """

    def __init__(self, path, handler):
        self.path = path
        self.handler = handler
        self.received = []
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(path)
        self._sock.listen(8)
        # A short accept deadline rather than a blocking accept: closing a
        # socket from another thread does not reliably wake a blocked accept()
        # on Linux, which would make every teardown pay the join timeout.
        self._sock.settimeout(0.05)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _read_request(conn) -> bytes:
        """Read headers, then exactly Content-Length bytes of body."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return buf
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    length = 0
        while len(body) < length:
            chunk = conn.recv(65536)
            if not chunk:
                break
            body += chunk
        return head + b"\r\n\r\n" + body

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                conn.settimeout(5.0)
                try:
                    self.received.append(self._read_request(conn))
                except OSError:
                    pass
                self.handler(conn)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def send_then_close(payload: bytes):
    def handler(conn):
        conn.sendall(payload)
    return handler


class FakeResponderCase(unittest.TestCase):
    """Base class giving each test a temp dir and a client factory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sock_path = os.path.join(self._tmp.name, "interlock.sock")

    def responder(self, handler):
        r = FakeResponder(self.sock_path, handler)
        self.addCleanup(r.close)
        return r

    def client(self, timeout=1.0, **kw):
        return PdpClient(self.sock_path, timeout=timeout, **kw)

    def assertBlocked(self, outcome: PepOutcome, reason=None):
        self.assertIsInstance(outcome, PepOutcome)
        self.assertFalse(outcome.permit, f"expected BLOCK, got permit with {outcome!r}")
        if reason is not None:
            self.assertEqual(outcome.reason, reason)


# ---------------------------------------------------------------------------
# Cases 1-6: every transport and protocol fault blocks.
# ---------------------------------------------------------------------------

class TestFailsClosed(FakeResponderCase):

    def test_01_no_socket_at_all(self):
        # Nothing was ever bound at this path.
        outcome = decide(self.client(), call())
        self.assertBlocked(outcome, PDP_UNAVAILABLE_REASON)

    def test_02_connection_refused_stale_socket_file(self):
        # A socket file left behind by a crashed PDP: the path exists, nothing
        # is listening. This is the realistic "PDP died" shape, and it must not
        # be mistaken for anything permissive.
        r = self.responder(send_then_close(b""))
        r.close()
        self.assertTrue(os.path.exists(self.sock_path), "stale socket file should remain")
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_03_timeout_responder_accepts_then_stalls(self):
        stalled = threading.Event()
        self.addCleanup(stalled.set)

        def handler(conn):
            stalled.wait(5.0)  # accept, then never answer

        self.responder(handler)
        outcome = decide(self.client(timeout=0.25), call())
        self.assertBlocked(outcome, PDP_UNAVAILABLE_REASON)

    def test_04_malformed_non_json_body(self):
        self.responder(send_then_close(http_response(b"<html>not json</html>")))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_04b_json_but_not_an_object(self):
        self.responder(send_then_close(http_response(b"[1, 2, 3]")))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_05_unknown_schema_version(self):
        body = envelope({"decision": "allow", "reason": "ok"}, schema_version=SCHEMA_VERSION + 1)
        self.responder(send_then_close(http_response(body)))
        # Note this would otherwise be an ALLOW. An unrecognized schema is not
        # negotiable down to "well, the decision field looks familiar".
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_06_unknown_decision_string(self):
        for bogus in ("banana", "ALLOW", "allowed", ""):
            with self.subTest(decision=bogus):
                r = self.responder(send_then_close(
                    http_response(envelope({"decision": bogus, "reason": "x"}))))
                self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)
                r.close()
                os.unlink(self.sock_path)

    def test_06b_pass_is_never_a_final_verdict(self):
        # PASS is a real Decision enum member (filters use it for "no
        # objection"), so a client that parsed decisions through the enum would
        # accept this. It must not: PASS in a final verdict is structurally
        # impossible and therefore evidence something is wrong.
        self.responder(send_then_close(http_response(envelope({"decision": "pass", "reason": ""}))))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_06c_modify_is_deferred_and_blocks(self):
        # MODIFY is deferred past v1. Until it is implemented end to end, a
        # MODIFY verdict is not something this client knows how to honor safely.
        self.responder(send_then_close(
            http_response(envelope({"decision": "modify", "modified_args": {"id": 2}}))))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_missing_verdict_key(self):
        self.responder(send_then_close(
            http_response(json.dumps({"schema_version": SCHEMA_VERSION}).encode())))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_decision_not_a_string(self):
        self.responder(send_then_close(http_response(envelope({"decision": 1}))))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_partial_read_body_shorter_than_content_length(self):
        # Declared 500 bytes, sent a handful, then closed. http.client raises
        # IncompleteRead; a truncated body must never be parsed opportunistically.
        self.responder(send_then_close(http_response(b'{"sch', content_length=500)))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_non_200_status(self):
        self.responder(send_then_close(
            http_response(envelope({"decision": "allow"}), status="500 Internal Server Error")))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_oversized_response(self):
        big = json.dumps({
            "schema_version": SCHEMA_VERSION,
            "verdict": {"decision": "allow", "reason": "x" * 5000},
        }).encode()
        self.responder(send_then_close(http_response(big)))
        client = self.client(max_response_bytes=512)

        # Assert at the evaluate() layer, because decide() flattens every
        # failure into the same reason string — which would let this test pass
        # even with the cap removed entirely (a truncated body is unparseable,
        # so it blocks either way). Naming the mechanism is what makes this
        # test able to fail if someone later reads the body unbounded.
        with self.assertRaises(PdpUnavailable) as ctx:
            client.evaluate(call())
        self.assertIn("oversized", str(ctx.exception))

        self.assertBlocked(decide(client, call()), PDP_UNAVAILABLE_REASON)

    def test_garbage_that_is_not_http_at_all(self):
        self.responder(send_then_close(b"\x00\x01\x02 not even http\r\n\r\n"))
        self.assertBlocked(decide(self.client(), call()), PDP_UNAVAILABLE_REASON)

    def test_evaluate_raises_pdp_unavailable_but_decide_does_not(self):
        # The two layers have different contracts on purpose: evaluate() raises
        # so a caller can distinguish; decide() is the enforcement entry point
        # and absorbs everything.
        client = self.client()
        with self.assertRaises(PdpUnavailable):
            client.evaluate(call())
        self.assertBlocked(decide(client, call()), PDP_UNAVAILABLE_REASON)


# ---------------------------------------------------------------------------
# The induced-fault case: an internal bug must still block, not escape.
# ---------------------------------------------------------------------------

class TestExceptionProof(FakeResponderCase):
    """
    Hermes swallows an exception raised by a pre_tool_call hook and then
    executes the tool (model_tools.py). In that harness an escaping exception is
    an ALLOW, so `decide` must be exception-proof rather than merely correct.
    H1's liveness check drives this same fault through the real harness.
    """

    def test_arbitrary_internal_exception_still_blocks(self):
        class Exploding(PdpClient):
            def evaluate(self, call):  # noqa: A002 - mirroring the base signature
                raise RuntimeError("induced fault: something unforeseen broke")

        outcome = decide(Exploding(self.sock_path), call())
        self.assertBlocked(outcome, PDP_UNAVAILABLE_REASON)

    def test_base_exception_types_that_are_not_transport_errors(self):
        for exc in (ValueError("bad"), KeyError("k"), TypeError("t"), AttributeError("a")):
            with self.subTest(exc=type(exc).__name__):
                class Exploding(PdpClient):
                    def evaluate(self, call, _e=exc):
                        raise _e

                self.assertBlocked(
                    decide(Exploding(self.sock_path), call()), PDP_UNAVAILABLE_REASON)

    def test_malformed_elevation_does_not_escape_as_keyerror(self):
        # wire.verdict_from_wire once indexed elevation fields raw. A HOLD whose
        # elevation is missing keys must degrade to a block, never to an
        # exception that a swallowing harness would turn into an allow.
        self.responder(send_then_close(http_response(
            envelope({"decision": "hold", "reason": "r", "elevation": {"capability": "x"}}))))
        outcome = decide(self.client(), call())
        self.assertBlocked(outcome)  # HOLD blocks; the point is that it did not raise

    def test_elevation_of_wrong_type_still_blocks(self):
        self.responder(send_then_close(http_response(
            envelope({"decision": "hold", "reason": "r", "elevation": "not-an-object"}))))
        self.assertBlocked(decide(self.client(), call()))


# ---------------------------------------------------------------------------
# Cases 7-9 and 12, against the real service over a real socket.
# ---------------------------------------------------------------------------

class RealServiceCase(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sock_path = os.path.join(self._tmp.name, "interlock.sock")

        self.policy = Policy.from_dict(POLICY)
        self.ledger = GrantLedger(StateStore(), threading.Lock())
        pipe = FilterPipeline(
            [RateLimiter(self.policy.rate_limit_config()), GateKeeper()],
            self.ledger,
            self.policy,
            authorizer=None,  # deferred HOLD
        )
        self.server = service.make_server(self.sock_path, pipe)
        t = threading.Thread(target=lambda: self.server.serve_forever(0.02), daemon=True)
        t.start()

        def _shutdown():
            self.server.shutdown()
            self.server.server_close()
            t.join(timeout=2)

        self.addCleanup(_shutdown)
        self.client = PdpClient(self.sock_path, timeout=5.0)


class TestAgainstRealService(RealServiceCase):

    def test_07_allow_when_a_grant_exists(self):
        self.ledger.mint("email:delete", {"id": 1}, uses=1, ttl=None, granted_by="operator")
        outcome = decide(self.client, call(args={"id": 1}))
        self.assertTrue(outcome.permit)
        self.assertEqual(outcome.decision, "allow")

    def test_07b_passive_tool_is_allowed_by_the_pdp_not_by_the_client(self):
        # The client does not classify. list_inbox is permitted because the PDP
        # resolved it to a passive effect, and it still cost a full round trip.
        outcome = decide(self.client, call(tool="list_inbox", args={}))
        self.assertTrue(outcome.permit)
        self.assertEqual(outcome.decision, "allow")

    def test_09_hold_blocks_and_surfaces_elevation(self):
        outcome = decide(self.client, call(args={"id": 7}))
        self.assertFalse(outcome.permit)
        self.assertEqual(outcome.decision, "hold")
        self.assertIsNotNone(outcome.elevation)
        self.assertEqual(outcome.elevation["capability"], "email:delete")
        self.assertEqual(outcome.elevation["scope"], {"id": 7})
        self.assertIn("email:delete", outcome.reason)
        self.assertIn("approval", outcome.reason)

    def test_08_deny_blocks_terminally(self):
        # A rate limit produces a genuine DENY (distinct from HOLD): the reason
        # is carried through verbatim so audit can tell a throttle from a policy
        # denial by exact string match.
        policy = Policy.from_dict({
            **POLICY,
            "rate_limits": {"key": "session_effect", "default": None,
                            "per_effect": {"email:delete": 1}},
        })
        ledger = GrantLedger(StateStore(), threading.Lock())
        pipe = FilterPipeline(
            [RateLimiter(policy.rate_limit_config()), GateKeeper()],
            ledger, policy, authorizer=None,
        )
        with tempfile.TemporaryDirectory() as d:
            sock = os.path.join(d, "s.sock")
            server = service.make_server(sock, pipe)
            t = threading.Thread(target=lambda: server.serve_forever(0.02), daemon=True)
            t.start()
            try:
                client = PdpClient(sock, timeout=5.0)
                first = decide(client, call(args={"id": 1}, call_id="a"))
                self.assertEqual(first.decision, "hold")  # budget spent on the attempt
                second = decide(client, call(args={"id": 2}, call_id="b"))
                self.assertFalse(second.permit)
                self.assertEqual(second.decision, "deny")
                self.assertEqual(second.reason, "rate_limited")
            finally:
                server.shutdown()
                server.server_close()
                t.join(timeout=2)

    def test_12_client_supplied_effect_is_stripped_and_ignored(self):
        # A shim that tries to declare delete_email "passive" must not be able
        # to. The client blanks the hint on the way out (defense in depth) AND
        # the PDP re-resolves from policy (invariant #4, the real boundary).
        outcome = decide(self.client, call(args={"id": 3}, effect="read"))
        self.assertFalse(outcome.permit, "a client-declared passive effect must not permit")
        self.assertEqual(outcome.decision, "hold")
        self.assertEqual(outcome.elevation["capability"], "email:delete")

    def test_12b_effect_is_blanked_on_the_wire(self):
        # Prove the stripping actually happens on the wire, not just that the
        # PDP happened to override it.
        sent = {}

        def handler(conn):
            conn.sendall(http_response(envelope({"decision": "deny", "reason": "x"})))

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "spy.sock")
            responder = FakeResponder(path, handler)
            try:
                decide(PdpClient(path, timeout=2.0), call(effect="read"))
                self.assertTrue(responder.received, "responder saw no request")
                body = responder.received[0].split(b"\r\n\r\n", 1)[1]
                sent = json.loads(body.decode("utf-8"))
            finally:
                responder.close()

        self.assertIsNone(sent["tool_call"]["effect"])
        self.assertEqual(sent["schema_version"], SCHEMA_VERSION)
        self.assertEqual(sent["tool_call"]["tool_name"], "delete_email")

    def test_single_use_grant_is_not_double_spent_through_this_client(self):
        # The runaway shape, driven by the Python client rather than the JS one:
        # one approval, many attempts, exactly one execution.
        self.ledger.mint("email:delete", {"id": 1}, uses=1, ttl=None, granted_by="operator")
        outcomes = [
            decide(self.client, call(args={"id": 1}, call_id=f"c{i}"))
            for i in range(5)
        ]
        self.assertEqual(sum(1 for o in outcomes if o.permit), 1)
        self.assertTrue(outcomes[0].permit)
        self.assertTrue(all(not o.permit for o in outcomes[1:]))


if __name__ == "__main__":
    unittest.main()
