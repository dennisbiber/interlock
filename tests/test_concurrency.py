"""
Concurrency safety of one shared PDP instance under simultaneous evaluate() calls.

This is the P4 headline property, but it holds at the pipeline level and needs no
transport: one FilterPipeline / GrantLedger / RateLimiter, many threads, a single
single-use grant -> exactly one ALLOW. Proves the ledger lock and the RateLimiter
lock together make concurrent evaluate() safe (no double-spend, no window race).
"""

import concurrent.futures
import threading
import unittest

from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall, Decision


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}


class TestSharedPipelineConcurrency(unittest.TestCase):
    def _run_contention(self, filters):
        ledger = GrantLedger(StateStore(), threading.Lock())
        policy = Policy.from_dict(POLICY)
        pipe = FilterPipeline(filters, ledger, policy, authorizer=None)  # deferred HOLD
        # Exactly one single-use grant for the contested action.
        ledger.mint("email:send", {"id": 1}, uses=1, ttl=None, granted_by="dennis")

        n = 64
        barrier = threading.Barrier(n)

        def worker(i):
            barrier.wait()
            # Distinct call_ids so the rate limiter treats them as separate attempts.
            return pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", f"c{i}")).decision

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = [f.result() for f in [ex.submit(worker, i) for i in range(n)]]

        allows = sum(r == Decision.ALLOW for r in results)
        self.assertEqual(allows, 1)  # the grant is spent exactly once
        # Everyone else is HELD (deferred, no authorizer wired).
        self.assertEqual(sum(r == Decision.HOLD for r in results), n - 1)
        return ledger

    def test_single_grant_one_allow_gate_only(self):
        self._run_contention([GateKeeper()])

    def test_single_grant_one_allow_with_rate_limiter_in_chain(self):
        # Unlimited limiter (default null) exercises its lock without denying,
        # so the full shared stack is proven concurrency-safe end to end.
        ledger = self._run_contention([RateLimiter({}), GateKeeper()])
        # The grant is gone (consumed once), not double-spent.
        self.assertEqual(ledger.all()[0].status, "CONSUMED")


if __name__ == "__main__":
    unittest.main()
