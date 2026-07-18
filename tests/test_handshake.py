"""P2 integration: kill switch, synchronous elevation handshake, filter ordering."""

import threading
import unittest
from dataclasses import replace

from interlock.authorizers.human import HumanApprover
from interlock.authorizers.policy import PolicyApprover
from interlock.filters.gatekeeper import GateKeeper
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.store.session_store import SessionStore
from interlock.types import ToolCall, Decision, FilterResult, GRANT_REVOKED

import tempfile


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}


class FakeChannel:
    def __init__(self, answer):
        self.answer = answer

    def ask(self, prompt):
        return self.answer


class StubFilter:
    def __init__(self, name, result, consumes=False):
        self.name = name
        self._result = result
        self.consumes = consumes
        self.calls = 0

    def evaluate(self, call, ctx):
        self.calls += 1
        return self._result


def build(authorizer=None, filters=None):
    ledger = GrantLedger(StateStore(), threading.Lock())
    policy = Policy.from_dict(POLICY)
    if authorizer == "human_yes":
        authorizer = HumanApprover(ledger, FakeChannel(True))
    elif authorizer == "human_no":
        authorizer = HumanApprover(ledger, FakeChannel(False))
    filters = [GateKeeper()] if filters is None else filters
    return FilterPipeline(filters, ledger, policy, authorizer=authorizer), ledger


# ---------------------------------------------------------------------------
# Kill switch (§7)
# ---------------------------------------------------------------------------

class TestKillSwitch(unittest.TestCase):
    def test_engaged_denies_everything_including_passive(self):
        pipe, ledger = build()
        ledger.engage_kill_switch("incident")
        self.assertEqual(pipe.evaluate(ToolCall("list_inbox", {}, "s", "c")).decision, Decision.DENY)
        self.assertEqual(pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c")).decision, Decision.DENY)

    def test_disengage_restores_normal_flow(self):
        pipe, ledger = build()
        ledger.engage_kill_switch()
        ledger.disengage_kill_switch()
        self.assertEqual(pipe.evaluate(ToolCall("list_inbox", {}, "s", "c")).decision, Decision.ALLOW)

    def test_kill_flag_persists_across_restart(self):
        with tempfile.TemporaryDirectory() as d:
            sessions = SessionStore(session_dir=d)
            l1 = GrantLedger(StateStore(), threading.Lock(), sessions=sessions)
            l1.engage_kill_switch("boom")
            l2 = GrantLedger(StateStore(), threading.Lock(), sessions=sessions)
            self.assertTrue(l2.is_killed())


# ---------------------------------------------------------------------------
# Synchronous handshake (§7)
# ---------------------------------------------------------------------------

class TestHandshake(unittest.TestCase):
    def test_human_yes_holds_then_mints_then_allows(self):
        pipe, _ = build(authorizer="human_yes")
        v = pipe.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c"))
        self.assertEqual(v.decision, Decision.ALLOW)
        self.assertIsNotNone(v.grant_id)

    def test_human_no_denies(self):
        pipe, _ = build(authorizer="human_no")
        v = pipe.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)

    def test_approval_is_single_use_runaway_still_stops(self):
        pipe, _ = build(authorizer="human_yes")
        # First call approved+consumed.
        self.assertEqual(pipe.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c1")).decision, Decision.ALLOW)
        # Handshake re-approves per call (single-use grants); each destructive
        # action requires its own yes. With human_no the loop would stop dead:
        pipe_no, _ = build(authorizer="human_no")
        self.assertEqual(pipe_no.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c2")).decision, Decision.DENY)

    def test_deferred_mode_returns_hold_when_no_authorizer(self):
        pipe, _ = build(authorizer=None)
        v = pipe.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c"))
        self.assertEqual(v.decision, Decision.HOLD)

    def test_policy_approver_auto_path(self):
        ledger = GrantLedger(StateStore(), threading.Lock())
        policy = Policy.from_dict(POLICY)
        approver = PolicyApprover(ledger, rule=lambda req: req.scope.get("id") == 7)
        pipe = FilterPipeline([GateKeeper()], ledger, policy, authorizer=approver)
        self.assertEqual(pipe.evaluate(ToolCall("delete_email", {"id": 7}, "s", "c")).decision, Decision.ALLOW)
        self.assertEqual(pipe.evaluate(ToolCall("delete_email", {"id": 8}, "s", "c")).decision, Decision.DENY)

    def test_unsatisfiable_mint_is_revoked_not_left_open(self):
        # A buggy authorizer mints a grant whose scope can't satisfy the re-run
        # gate. The pipeline must revoke the orphan and deny, not leave it OPEN.
        ledger = GrantLedger(StateStore(), threading.Lock())
        policy = Policy.from_dict(POLICY)

        class MismatchAuthorizer:
            name = "Mismatch"

            def __init__(self, led):
                self._led = led

            def authorize(self, req):
                # Wrong scope on purpose: {"id": -999} won't match the call's {"id": 123}.
                return self._led.mint(req.capability, {"id": -999}, uses=1, ttl=120, granted_by="buggy")

        pipe = FilterPipeline([GateKeeper()], ledger, policy, authorizer=MismatchAuthorizer(ledger))
        v = pipe.evaluate(ToolCall("delete_email", {"id": 123}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)
        grants = ledger.all()
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0].status, GRANT_REVOKED)  # not OPEN


# ---------------------------------------------------------------------------
# Construction-time ordering check
# ---------------------------------------------------------------------------

class TestFilterOrdering(unittest.TestCase):
    def _passing(self, name, consumes=False):
        return StubFilter(name, FilterResult(Decision.PASS, "pass"), consumes=consumes)

    def test_non_consuming_after_consuming_raises(self):
        with self.assertRaises(ValueError):
            build(filters=[GateKeeper(), self._passing("rate")])

    def test_consuming_last_is_ok(self):
        pipe, _ = build(filters=[self._passing("rate"), GateKeeper()])
        self.assertEqual(pipe.evaluate(ToolCall("list_inbox", {}, "s", "c")).decision, Decision.ALLOW)

    def test_single_consuming_filter_is_ok(self):
        pipe, _ = build(filters=[GateKeeper()])
        self.assertEqual(pipe.evaluate(ToolCall("list_inbox", {}, "s", "c")).decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
