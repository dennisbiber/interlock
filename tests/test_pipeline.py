"""P1 FilterPipeline tests — effect resolution, chain composition, end-to-end gating."""

import threading
import unittest
from dataclasses import replace
from pathlib import Path

from interlock.filters.gatekeeper import GateKeeper
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall, Verdict, FilterResult, Decision


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}


def make_pipeline(filters, policy_dict=POLICY):
    ledger = GrantLedger(StateStore(), threading.Lock())
    policy = Policy.from_dict(policy_dict)
    return FilterPipeline(filters, ledger, policy), ledger


class StubFilter:
    """A filter that returns a canned FilterResult and counts its invocations."""

    def __init__(self, name, result):
        self.name = name
        self._result = result
        self.calls = 0

    def evaluate(self, call, ctx):
        self.calls += 1
        return self._result


# ---------------------------------------------------------------------------
# Effect resolution (invariant #4)
# ---------------------------------------------------------------------------

class TestEffectResolution(unittest.TestCase):
    def test_adapter_effect_hint_is_ignored(self):
        pipe, _ = make_pipeline([GateKeeper()])
        # Adapter lies: claims a destructive tool is a passive "read".
        call = ToolCall("delete_email", {"id": 1}, "s", "c", effect="read")
        v = pipe.evaluate(call)
        self.assertEqual(v.decision, Decision.HOLD)  # resolved as email:send, not passive

    def test_passive_tool_allowed(self):
        pipe, _ = make_pipeline([GateKeeper()])
        v = pipe.evaluate(ToolCall("list_inbox", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.ALLOW)

    def test_unclassified_tool_gated(self):
        pipe, _ = make_pipeline([GateKeeper()])
        v = pipe.evaluate(ToolCall("wire_money", {"amt": 100}, "s", "c"))
        self.assertEqual(v.decision, Decision.HOLD)

    def test_unclassified_tool_denied_without_elevation(self):
        pipe, _ = make_pipeline([GateKeeper()], {"passive_effects": ["read"], "elevation": {}})
        v = pipe.evaluate(ToolCall("wire_money", {"amt": 100}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)


# ---------------------------------------------------------------------------
# Composition semantics (§5)
# ---------------------------------------------------------------------------

class TestComposition(unittest.TestCase):
    def _pass(self, name="p"):
        return StubFilter(name, FilterResult(Decision.PASS, "pass"))

    def test_all_pass_allows(self):
        pipe, _ = make_pipeline([self._pass("a"), self._pass("b")])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.ALLOW)

    def test_deny_short_circuits(self):
        deny = StubFilter("deny", FilterResult(Decision.DENY, "nope"))
        later = self._pass("later")
        pipe, _ = make_pipeline([deny, later])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)
        self.assertEqual(later.calls, 0)  # never reached

    def test_hold_remembered(self):
        hold = StubFilter("hold", FilterResult(Decision.HOLD, "held"))
        pipe, _ = make_pipeline([self._pass("a"), hold])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.HOLD)

    def test_later_deny_beats_earlier_hold(self):
        hold = StubFilter("hold", FilterResult(Decision.HOLD, "held"))
        deny = StubFilter("deny", FilterResult(Decision.DENY, "nope"))
        pipe, _ = make_pipeline([hold, deny])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)

    def test_hold_beats_modify(self):
        modify = StubFilter("mod", FilterResult(Decision.MODIFY, "m", modified_args={"x": 1}))
        hold = StubFilter("hold", FilterResult(Decision.HOLD, "held"))
        pipe, _ = make_pipeline([modify, hold])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.HOLD)

    def test_modify_accumulates(self):
        m1 = StubFilter("m1", FilterResult(Decision.MODIFY, "m1", modified_args={"a": 1}))
        m2 = StubFilter("m2", FilterResult(Decision.MODIFY, "m2", modified_args={"b": 2}))
        pipe, _ = make_pipeline([m1, m2])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.MODIFY)
        self.assertEqual(v.modified_args, {"a": 1, "b": 2})

    def test_grant_id_propagates_to_verdict(self):
        allow = StubFilter("gate", FilterResult(Decision.ALLOW, "consumed", grant_id="g-42"))
        pipe, _ = make_pipeline([allow])
        v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
        self.assertEqual(v.decision, Decision.ALLOW)
        self.assertEqual(v.grant_id, "g-42")


# ---------------------------------------------------------------------------
# End-to-end (the §9 flow at the pipeline level; authorizer simulated by a
# direct mint, since real authorizers arrive in P2)
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):
    def test_gate_then_grant_then_reissue_then_runaway_stop(self):
        pipe, ledger = make_pipeline([GateKeeper()])
        call = ToolCall("delete_email", {"id": 123}, "s", "c1")

        v1 = pipe.evaluate(call)
        self.assertEqual(v1.decision, Decision.HOLD)
        self.assertEqual(v1.elevation.scope, {"id": 123})

        # A human approves -> authorizer would mint a single-use grant (P2).
        ledger.mint("email:send", {"id": 123}, uses=1, ttl=120, granted_by="dennis")

        v2 = pipe.evaluate(replace(call, call_id="c2"))
        self.assertEqual(v2.decision, Decision.ALLOW)
        self.assertIsNotNone(v2.grant_id)

        # Agent loops to delete again: the grant is spent, so it holds once more.
        v3 = pipe.evaluate(replace(call, call_id="c3"))
        self.assertEqual(v3.decision, Decision.HOLD)


# ---------------------------------------------------------------------------
# The shipped example policy.json parses and behaves.
# ---------------------------------------------------------------------------

class TestShippedPolicy(unittest.TestCase):
    def setUp(self):
        self.policy_path = Path(__file__).resolve().parents[1] / "policy.json"

    def test_policy_file_loads(self):
        policy = Policy.from_file(self.policy_path)
        # delete_email is classified by what it DOES (email:delete), not by the
        # adjacent-sounding email:send. Effect names are the capability
        # vocabulary grants are minted against, so a wrong name here would mint
        # the wrong capability.
        self.assertEqual(policy.classify("delete_email"), ("email:delete", False))
        self.assertEqual(policy.classify("list_inbox"), ("read", True))
        self.assertEqual(policy.classify("unknown_tool"), ("unknown_tool", False))
        self.assertEqual(policy.project_scope("delete_email", {"id": 9, "z": 1}), {"id": 9})
        self.assertEqual(policy.elevation_for("email:delete"), "HumanApprover")
        self.assertEqual(policy.elevation_for("email:send"), "HumanApprover")
        self.assertEqual(policy.elevation_for("fs:delete"), "HumanApprover")  # via default

    def test_shipped_rate_limits_load_with_null_default(self):
        rl = Policy.from_file(self.policy_path).rate_limit_config()
        self.assertEqual(rl["key"], "session_effect")
        self.assertIsNone(rl["default"])            # unlimited unless opted in
        self.assertEqual(rl["per_effect"]["email:send"], 5)


if __name__ == "__main__":
    unittest.main()
