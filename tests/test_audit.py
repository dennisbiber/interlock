"""P3 AuditLog tests — JSONL sink + the audit funnel over every evaluate() exit."""

import os
import tempfile
import threading
import unittest

from interlock.audit import JsonlAuditLog
from interlock.authorizers.human import HumanApprover
from interlock.filters.gatekeeper import GateKeeper
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import ToolCall, Decision, FilterResult


POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
}
POLICY_NO_ELEV = {
    "passive_effects": ["read"],
    "tool_effects": {"delete_email": "email:send"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {},
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

    def evaluate(self, call, ctx):
        return self._result


def build(audit_path, policy=POLICY, authorizer=None, filters=None):
    ledger = GrantLedger(StateStore(), threading.Lock())
    pol = Policy.from_dict(policy)
    if authorizer == "human_yes":
        authorizer = HumanApprover(ledger, FakeChannel(True))
    elif authorizer == "human_no":
        authorizer = HumanApprover(ledger, FakeChannel(False))
    audit = JsonlAuditLog(audit_path)
    filters = [GateKeeper()] if filters is None else filters
    return FilterPipeline(filters, ledger, pol, authorizer=authorizer, audit=audit), ledger, audit


class TestJsonlAuditLog(unittest.TestCase):
    def test_append_and_read_back(self):
        with tempfile.TemporaryDirectory() as d:
            log = JsonlAuditLog(os.path.join(d, "audit.jsonl"))
            log.record({"a": 1})
            log.record({"b": 2})
            self.assertEqual(log.read_all(), [{"a": 1}, {"b": 2}])

    def test_record_never_raises_on_bad_path(self):
        # A path that can't be written must be swallowed, not raised — but logged
        # loudly. assertLogs both verifies the loud log and captures the output.
        log = JsonlAuditLog("/proc/should-not-be-writable/audit.jsonl")
        with self.assertLogs("interlock.audit", level="ERROR"):
            log.record({"a": 1})  # must not raise


class TestAuditFunnelExitPaths(unittest.TestCase):
    """Every exit path of evaluate() writes exactly one record."""

    def _one(self, fn):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            records = fn(path)
            return records

    def test_allow_writes_one(self):
        def run(path):
            pipe, _, audit = build(path)
            pipe.evaluate(ToolCall("list_inbox", {}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "allow")

    def test_deny_writes_one(self):
        def run(path):
            pipe, _, audit = build(path, policy=POLICY_NO_ELEV)
            pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "deny")

    def test_hold_deferred_writes_one(self):
        def run(path):
            pipe, _, audit = build(path, authorizer=None)
            pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "hold")

    def test_hold_resolved_writes_exactly_one_despite_rerun(self):
        # The chain runs twice (mint + re-issue); audit must still write ONCE.
        def run(path):
            pipe, _, audit = build(path, authorizer="human_yes")
            pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "allow")
        self.assertEqual(recs[0]["handshake"], "approved")
        self.assertIsNotNone(recs[0]["grant_id"])

    def test_hold_denied_by_authorizer_writes_one(self):
        def run(path):
            pipe, _, audit = build(path, authorizer="human_no")
            pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "deny")
        self.assertEqual(recs[0]["handshake"], "denied")

    def test_kill_switch_early_return_writes_one(self):
        def run(path):
            pipe, ledger, audit = build(path)
            ledger.engage_kill_switch("incident")
            pipe.evaluate(ToolCall("list_inbox", {}, "s", "c"))
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "deny")
        self.assertEqual(recs[0]["reason"], "kill switch engaged")

    def test_unknown_filter_decision_fail_closed_writes_one(self):
        def run(path):
            bogus = StubFilter("bogus", FilterResult("not-a-decision", "weird"))  # type: ignore[arg-type]
            pipe, _, audit = build(path, filters=[bogus])
            v = pipe.evaluate(ToolCall("t", {}, "s", "c"))
            self.assertEqual(v.decision, Decision.DENY)  # fail closed
            return audit.read_all()
        recs = self._one(run)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["decision"], "deny")


class TestAuditRecordShape(unittest.TestCase):
    def test_record_has_expected_fields(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            pipe, _, audit = build(path, authorizer="human_yes")
            pipe.evaluate(ToolCall("delete_email", {"id": 5}, "sess-9", "call-9"))
            rec = audit.read_all()[0]
            for field in ("ts", "session_id", "call_id", "tool_name", "effect",
                          "decision", "reason", "grant_id", "handshake"):
                self.assertIn(field, rec)
            self.assertEqual(rec["session_id"], "sess-9")
            self.assertEqual(rec["call_id"], "call-9")
            self.assertEqual(rec["tool_name"], "delete_email")
            self.assertEqual(rec["effect"], "email:send")


class TestAuditFailureIsolation(unittest.TestCase):
    def test_sink_that_raises_does_not_crash_or_flip_verdict(self):
        class ExplodingSink:
            def record(self, entry):
                raise RuntimeError("disk on fire")

        ledger = GrantLedger(StateStore(), threading.Lock())
        pol = Policy.from_dict(POLICY_NO_ELEV)
        pipe = FilterPipeline([GateKeeper()], ledger, pol, audit=ExplodingSink())
        # The call would be DENIED; a failing audit must not turn it into ALLOW,
        # nor propagate the exception.
        v = pipe.evaluate(ToolCall("delete_email", {"id": 1}, "s", "c"))
        self.assertEqual(v.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
