"""P3 RateLimiter tests — isolation and pipeline integration."""

import threading
import unittest
from unittest import mock

from interlock.authorizers.human import HumanApprover
from interlock.filters.base import FilterContext
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger, ConsumeOnlyView
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall, Decision, RATE_LIMITED_REASON


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}


def ctx_for(policy_dict=POLICY):
    ledger = GrantLedger(StateStore(), threading.Lock())
    return FilterContext(ledger=ConsumeOnlyView(ledger), policy=Policy.from_dict(policy_dict))


def call(tool="delete_email", args=None, session="s", cid="c1"):
    return ToolCall(tool, args if args is not None else {"id": 1}, session, cid)


class FakeChannel:
    def __init__(self, answer):
        self.answer = answer

    def ask(self, prompt):
        return self.answer


# ---------------------------------------------------------------------------
# Construction / config validation
# ---------------------------------------------------------------------------

class TestConstruction(unittest.TestCase):
    def test_unknown_key_rejected(self):
        with self.assertRaises(ValueError):
            RateLimiter({"key": "per_ip"})

    def test_default_key_is_session_effect(self):
        rl = RateLimiter({})
        self.assertEqual(rl._key_mode, "session_effect")


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------

class TestRateLimiterIsolation(unittest.TestCase):
    def test_under_limit_passes(self):
        rl = RateLimiter({"per_effect": {"email:send": 2}})
        ctx = ctx_for()
        self.assertEqual(rl.evaluate(call(cid="a"), ctx).decision, Decision.PASS)
        self.assertEqual(rl.evaluate(call(cid="b"), ctx).decision, Decision.PASS)

    def test_over_limit_denies_with_reserved_reason(self):
        rl = RateLimiter({"per_effect": {"email:send": 1}})
        ctx = ctx_for()
        self.assertEqual(rl.evaluate(call(cid="a"), ctx).decision, Decision.PASS)
        r = rl.evaluate(call(cid="b"), ctx)
        self.assertEqual(r.decision, Decision.DENY)
        self.assertEqual(r.reason, RATE_LIMITED_REASON)

    def test_zero_limit_blocks_effect_entirely(self):
        rl = RateLimiter({"per_effect": {"email:send": 0}})
        self.assertEqual(rl.evaluate(call(cid="a"), ctx_for()).decision, Decision.DENY)

    def test_passive_effects_not_limited(self):
        rl = RateLimiter({"default": 0})  # even a 0 default must not touch passive reads
        ctx = ctx_for()
        for i in range(5):
            self.assertEqual(rl.evaluate(call("list_inbox", {}, cid=str(i)), ctx).decision, Decision.PASS)

    def test_unlimited_when_no_limit_configured(self):
        rl = RateLimiter({"default": None})  # unlimited
        ctx = ctx_for()
        for i in range(10):
            self.assertEqual(rl.evaluate(call(cid=str(i)), ctx).decision, Decision.PASS)

    def test_session_effect_key_isolates_effects(self):
        policy = {
            "tool_effects": {"delete_email": "email:send", "rm": "fs:delete"},
            "tool_scopes": {}, "passive_effects": [], "elevation": {"default": "x"},
        }
        rl = RateLimiter({"key": "session_effect", "per_effect": {"email:send": 1, "fs:delete": 1}})
        ctx = ctx_for(policy)
        self.assertEqual(rl.evaluate(call("delete_email", cid="a"), ctx).decision, Decision.PASS)
        # Different effect, same session -> independent budget.
        self.assertEqual(rl.evaluate(call("rm", {"path": "/x"}, cid="b"), ctx).decision, Decision.PASS)
        # email:send is now exhausted.
        self.assertEqual(rl.evaluate(call("delete_email", cid="c"), ctx).decision, Decision.DENY)

    def test_session_key_isolates_sessions(self):
        rl = RateLimiter({"key": "session", "per_effect": {"email:send": 1}})
        ctx = ctx_for()
        self.assertEqual(rl.evaluate(call(session="s1", cid="a"), ctx).decision, Decision.PASS)
        self.assertEqual(rl.evaluate(call(session="s2", cid="b"), ctx).decision, Decision.PASS)
        self.assertEqual(rl.evaluate(call(session="s1", cid="c"), ctx).decision, Decision.DENY)

    def test_window_resets(self):
        ctx = ctx_for()
        with mock.patch("interlock.filters.rate_limiter._now", return_value=1000.0):
            rl = RateLimiter({"window_seconds": 60, "per_effect": {"email:send": 1}})
            self.assertEqual(rl.evaluate(call(cid="a"), ctx).decision, Decision.PASS)
            self.assertEqual(rl.evaluate(call(cid="b"), ctx).decision, Decision.DENY)
        with mock.patch("interlock.filters.rate_limiter._now", return_value=1061.0):
            self.assertEqual(rl.evaluate(call(cid="c"), ctx).decision, Decision.PASS)

    def test_same_callid_not_double_counted(self):
        rl = RateLimiter({"per_effect": {"email:send": 1}})
        ctx = ctx_for()
        # Same call_id twice: counts once, so both PASS (second is deduped).
        self.assertEqual(rl.evaluate(call(cid="dup"), ctx).decision, Decision.PASS)
        self.assertEqual(rl.evaluate(call(cid="dup"), ctx).decision, Decision.PASS)
        # A different call_id is now over the limit.
        self.assertEqual(rl.evaluate(call(cid="other"), ctx).decision, Decision.DENY)

    def test_concurrent_attempts_exactly_k_pass(self):
        # N threads through a barrier contend for one (session, effect) budget of
        # K. The lock must make check-then-increment atomic: exactly K PASS.
        import concurrent.futures

        K, N = 5, 64
        rl = RateLimiter({"per_effect": {"email:send": K}})
        ctx = ctx_for()
        barrier = threading.Barrier(N)

        def worker(i):
            barrier.wait()
            return rl.evaluate(call(cid=f"c{i}"), ctx).decision  # distinct call_ids

        with concurrent.futures.ThreadPoolExecutor(max_workers=N) as ex:
            results = [f.result() for f in [ex.submit(worker, i) for i in range(N)]]

        self.assertEqual(sum(r == Decision.PASS for r in results), K)
        self.assertEqual(sum(r == Decision.DENY for r in results), N - K)


# ---------------------------------------------------------------------------
# Pipeline integration (the two required guards)
# ---------------------------------------------------------------------------

class TestRateLimiterInPipeline(unittest.TestCase):
    def _pipe(self, rl_config, authorizer=None):
        ledger = GrantLedger(StateStore(), threading.Lock())
        policy = Policy.from_dict(POLICY)
        if authorizer == "human_yes":
            authorizer = HumanApprover(ledger, FakeChannel(True))
        pipe = FilterPipeline([RateLimiter(rl_config), GateKeeper()], ledger, policy, authorizer=authorizer)
        return pipe, ledger

    def test_ratelimit_denies_before_gate_consumes_no_grant_burned(self):
        # Hard ceiling of 0 on email:send: throttle fires before the gate.
        pipe, ledger = self._pipe({"per_effect": {"email:send": 0}})
        # A valid grant exists for this exact call...
        ledger.mint("email:send", {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        v = pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c1"))
        self.assertEqual(v.decision, Decision.DENY)
        self.assertEqual(v.reason, RATE_LIMITED_REASON)
        # ...and it was NOT consumed, because the limiter short-circuited first.
        self.assertIsNotNone(ledger.find_and_consume("email:send", {"id": 1}))

    def test_resolve_hold_rerun_counts_callid_once(self):
        # Limit 1, human approves. One logical call must ALLOW (a naive limiter
        # would DENY the post-mint re-run), and a second distinct call is denied.
        pipe, _ = self._pipe({"per_effect": {"email:send": 1}}, authorizer="human_yes")
        v1 = pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c1"))
        self.assertEqual(v1.decision, Decision.ALLOW)  # re-run not double-counted
        v2 = pipe.evaluate(ToolCall("delete_email", {"id": 2}, "s", "c2"))
        self.assertEqual(v2.decision, Decision.DENY)   # budget of 1 already spent
        self.assertEqual(v2.reason, RATE_LIMITED_REASON)


if __name__ == "__main__":
    unittest.main()
