"""P1 GateKeeper tests — the §6 decision table in isolation."""

import threading
import unittest

from interlock.filters.base import FilterContext
from interlock.filters.gatekeeper import GateKeeper
from interlock.ledger import GrantLedger, ConsumeOnlyView
from interlock.pipeline import Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall, Decision


def make_ctx(policy_dict):
    ledger = GrantLedger(StateStore(), threading.Lock())
    policy = Policy.from_dict(policy_dict)
    ctx = FilterContext(ledger=ConsumeOnlyView(ledger), policy=policy)
    return ctx, ledger, policy


DEFAULT_POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}


class TestGateKeeper(unittest.TestCase):
    def setUp(self):
        self.gate = GateKeeper()

    def test_passive_effect_passes(self):
        ctx, _, _ = make_ctx(DEFAULT_POLICY)
        call = ToolCall("list_inbox", {}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.PASS)

    def test_consequential_no_grant_holds_when_elevation_configured(self):
        ctx, _, _ = make_ctx(DEFAULT_POLICY)
        call = ToolCall("delete_email", {"id": 123}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.HOLD)
        self.assertIsNotNone(r.elevation)
        self.assertEqual(r.elevation.capability, "email:send")
        self.assertEqual(r.elevation.scope, {"id": 123})

    def test_consequential_with_grant_allows_and_consumes(self):
        ctx, ledger, _ = make_ctx(DEFAULT_POLICY)
        ledger.mint("email:send", {"id": 123}, uses=1, ttl=None, granted_by="dennis")
        call = ToolCall("delete_email", {"id": 123}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.ALLOW)
        self.assertIsNotNone(r.grant_id)
        # single-use spent -> next attempt holds again
        r2 = self.gate.evaluate(call, ctx)
        self.assertEqual(r2.decision, Decision.HOLD)

    def test_consequential_no_elevation_denies(self):
        policy = {"passive_effects": ["read"], "tool_effects": {"rm": "fs:delete"}, "elevation": {}}
        ctx, _, _ = make_ctx(policy)
        call = ToolCall("rm", {"path": "/x"}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.DENY)

    def test_unclassified_tool_is_consequential(self):
        ctx, _, _ = make_ctx(DEFAULT_POLICY)
        call = ToolCall("wire_money", {"amt": 100}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.HOLD)  # default elevation -> HOLD, not silent allow
        self.assertEqual(r.elevation.capability, "wire_money")

    def test_scope_projection_ignores_volatile_args(self):
        ctx, ledger, _ = make_ctx(DEFAULT_POLICY)
        # Grant is scoped to the stable id only; a nonce in args must not break matching.
        ledger.mint("email:send", {"id": 123}, uses=1, ttl=None, granted_by="dennis")
        call = ToolCall("delete_email", {"id": 123, "nonce": "abc", "ts": 999}, "s", "c")
        r = self.gate.evaluate(call, ctx)
        self.assertEqual(r.decision, Decision.ALLOW)

    def test_gate_cannot_mint(self):
        # The consume-only view is the only ledger surface the gate ever sees.
        ctx, _, _ = make_ctx(DEFAULT_POLICY)
        self.assertFalse(hasattr(ctx.ledger, "mint"))
        self.assertFalse(hasattr(ctx.ledger, "revoke"))
        with self.assertRaises(AttributeError):
            ctx.ledger.mint("email:send", {}, 1, None, "self")  # type: ignore[attr-defined]


if __name__ == "__main__":
    unittest.main()
