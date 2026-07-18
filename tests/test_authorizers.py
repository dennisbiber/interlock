"""P2 authorizer tests — HumanApprover, PolicyApprover, Channel."""

import threading
import unittest

from interlock.authorizers.human import HumanApprover, StdinChannel
from interlock.authorizers.policy import PolicyApprover
from interlock.ledger import GrantLedger
from interlock.store.state_store import StateStore
from interlock.types import ElevationRequest, ToolCall, GRANT_OPEN


def make_ledger():
    return GrantLedger(StateStore(), threading.Lock())


def make_request(cap="email:send", scope=None):
    scope = {"id": 123} if scope is None else scope
    call = ToolCall("delete_email", {"id": 123}, "s", "c")
    return ElevationRequest(call=call, capability=cap, scope=scope, reason="needs elevation")


class FakeChannel:
    def __init__(self, answer: bool):
        self.answer = answer
        self.prompts = []

    def ask(self, prompt: str) -> bool:
        self.prompts.append(prompt)
        return self.answer


class TestHumanApprover(unittest.TestCase):
    def test_yes_mints_single_use_grant_matching_request(self):
        ledger = make_ledger()
        approver = HumanApprover(ledger, FakeChannel(True), ttl=60)
        req = make_request()
        grant = approver.authorize(req)
        self.assertIsNotNone(grant)
        self.assertEqual(grant.capability, "email:send")
        self.assertEqual(grant.scope, {"id": 123})
        self.assertEqual(grant.uses_left, 1)
        self.assertEqual(grant.status, GRANT_OPEN)
        self.assertEqual(grant.granted_by, "human")
        # And it's really in the ledger, consumable exactly once.
        self.assertIsNotNone(ledger.find_and_consume("email:send", {"id": 123}))
        self.assertIsNone(ledger.find_and_consume("email:send", {"id": 123}))

    def test_no_mints_nothing(self):
        ledger = make_ledger()
        approver = HumanApprover(ledger, FakeChannel(False))
        self.assertIsNone(approver.authorize(make_request()))
        self.assertEqual(ledger.all(), [])

    def test_prompt_includes_tool_and_scope(self):
        ch = FakeChannel(True)
        HumanApprover(make_ledger(), ch).authorize(make_request())
        self.assertEqual(len(ch.prompts), 1)
        self.assertIn("delete_email", ch.prompts[0])
        self.assertIn("email:send", ch.prompts[0])


class TestStdinChannel(unittest.TestCase):
    def test_reads_yes_no_from_streams(self):
        import io
        yes = StdinChannel(in_stream=io.StringIO("yes\n"), out_stream=io.StringIO())
        no = StdinChannel(in_stream=io.StringIO("\n"), out_stream=io.StringIO())
        self.assertTrue(yes.ask("go?"))
        self.assertFalse(no.ask("go?"))


class TestPolicyApprover(unittest.TestCase):
    def test_rule_true_mints_single_use(self):
        ledger = make_ledger()
        approver = PolicyApprover(ledger, rule=lambda req: req.capability == "email:send")
        grant = approver.authorize(make_request())
        self.assertIsNotNone(grant)
        self.assertEqual(grant.uses_left, 1)
        self.assertEqual(grant.granted_by, "policy")

    def test_rule_false_refuses(self):
        ledger = make_ledger()
        approver = PolicyApprover(ledger, rule=lambda req: False)
        self.assertIsNone(approver.authorize(make_request()))
        self.assertEqual(ledger.all(), [])

    def test_rule_can_discriminate_on_scope(self):
        ledger = make_ledger()
        # Only auto-approve deletions of a specific safe id.
        approver = PolicyApprover(ledger, rule=lambda req: req.scope.get("id") == 1)
        self.assertIsNone(approver.authorize(make_request(scope={"id": 999})))
        self.assertIsNotNone(approver.authorize(make_request(scope={"id": 1})))


if __name__ == "__main__":
    unittest.main()
