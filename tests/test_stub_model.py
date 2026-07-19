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


class TestRetryCalls(unittest.TestCase):
    """
    Step 7b needs the approved command attempted more than once, and each
    attempt must be ALONE IN ITS OWN TURN.

    hermes-agent's run_agent._deduplicate_tool_calls removes duplicate
    (tool_name, arguments) pairs within a single turn. Retries batched together
    are stripped before dispatch and never reach the PDP, so the run looks
    exactly like a normal one and the double-spend check silently proves
    nothing. That is how the first version of this check passed while testing
    nothing at all.
    """

    def test_first_turn_is_one_call_per_victim(self):
        calls = stub_model.tool_calls()
        self.assertEqual(len(calls), stub_model.N_CALLS)
        approved = f"{stub_model.VICTIM_DIR}/{stub_model.APPROVED_INDEX}.txt"
        targeting = [
            c for c in calls
            if json.loads(c["function"]["arguments"])["command"].endswith(approved)
        ]
        self.assertEqual(len(targeting), 1, "the approved path appears once in turn 1")

    def test_each_retry_is_alone_in_its_turn(self):
        for attempt in (1, 2, 3):
            with self.subTest(attempt=attempt):
                calls = stub_model.retry_call(attempt)
                self.assertEqual(
                    len(calls), 1,
                    "batching retries would trip Hermes's within-turn dedup")

    def test_retries_target_the_approved_command_exactly(self):
        approved_cmd = json.loads(
            stub_model.tool_calls()[stub_model.APPROVED_INDEX]["function"]["arguments"]
        )["command"]
        retry_cmd = json.loads(
            stub_model.retry_call(1)[0]["function"]["arguments"]
        )["command"]
        # Byte-identical, or the grant's scope would not match and the retry
        # would be denied for the wrong reason.
        self.assertEqual(retry_cmd, approved_cmd)

    def test_retry_ids_are_distinct(self):
        ids = {stub_model.retry_call(n)[0]["id"] for n in range(1, 6)}
        self.assertEqual(len(ids), 5)


class TestTurnSelection(unittest.TestCase):

    def test_batch_count_tracks_assistant_tool_turns(self):
        self.assertEqual(stub_model.dispatched_batches({"messages": [{"role": "user"}]}), 0)
        self.assertEqual(stub_model.dispatched_batches({"messages": [
            {"role": "assistant", "tool_calls": [{"id": "a"}]},
            {"role": "tool", "content": "{}"},
        ]}), 1)
        self.assertEqual(stub_model.dispatched_batches({"messages": [
            {"role": "assistant", "tool_calls": [{"id": "a"}]},
            {"role": "tool", "content": "{}"},
            {"role": "assistant", "tool_calls": [{"id": "b"}]},
            {"role": "tool", "content": "{}"},
        ]}), 2)

    def test_zero_duplicates_is_the_default_shape(self):
        self.assertEqual(stub_model.DUPLICATE_APPROVED, 0)
