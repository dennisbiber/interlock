"""
Regression tests for the negative-control stub model.

The stub originally picked its script by counting requests. hermes-agent issues
its own requests to the completions endpoint around the user's turn, so the
counter handed the wrong script to the wrong call: the agent received "Finished"
as its FIRST response, dispatched nothing, and the experiment reported 50
survivors with no error — a false pass that looks exactly like enforcement
working perfectly.

A silently-wrong experiment is worse than a broken one, so the selection is
keyed off conversation state and pinned here.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "experiments", "hermes-negative-control"))

import stub_model  # noqa: E402


class TestScriptSelection(unittest.TestCase):

    def test_fresh_conversation_gets_tool_calls(self):
        body = {"messages": [{"role": "user", "content": "delete them"}]}
        self.assertFalse(stub_model._already_dispatched(body))

    def test_conversation_with_tool_results_is_finished(self):
        body = {"messages": [
            {"role": "user", "content": "delete them"},
            {"role": "assistant", "tool_calls": [{"id": "c0"}]},
            {"role": "tool", "tool_call_id": "c0", "content": "{}"},
        ]}
        self.assertTrue(stub_model._already_dispatched(body))

    def test_assistant_tool_calls_alone_already_count(self):
        body = {"messages": [{"role": "assistant", "tool_calls": [{"id": "c0"}]}]}
        self.assertTrue(stub_model._already_dispatched(body))

    def test_missing_or_malformed_messages_do_not_explode(self):
        for body in ({}, {"messages": None}, {"messages": ["not-a-dict"]}):
            with self.subTest(body=body):
                self.assertFalse(stub_model._already_dispatched(body))

    def test_extra_preflight_requests_do_not_consume_the_script(self):
        # The exact failure: several requests arrive before any tool result
        # exists. Every one of them must still get the tool-call script.
        fresh = {"messages": [{"role": "user", "content": "go"}]}
        for _ in range(5):
            self.assertFalse(stub_model._already_dispatched(fresh))


class TestToolCallScript(unittest.TestCase):

    def test_one_call_per_victim_and_all_distinct(self):
        calls = stub_model.tool_calls()
        self.assertEqual(len(calls), stub_model.N_CALLS)
        self.assertEqual(len({c["id"] for c in calls}), stub_model.N_CALLS)
        for call in calls:
            self.assertEqual(call["function"]["name"], "terminal")
            args = json.loads(call["function"]["arguments"])
            self.assertIn("rm -f", args["command"])
            self.assertIn(stub_model.VICTIM_DIR, args["command"])


if __name__ == "__main__":
    unittest.main()
