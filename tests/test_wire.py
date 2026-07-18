"""P4 wire schema tests — round-trip identity and the enum-serialization guard."""

import json
import unittest

from interlock.types import ToolCall, Verdict, Decision, ElevationRequest
from interlock.wire import (
    SCHEMA_VERSION,
    WireError,
    toolcall_to_wire,
    toolcall_from_wire,
    verdict_to_wire,
    verdict_from_wire,
    wrap_request,
    wrap_response,
)


class TestToolCallWire(unittest.TestCase):
    def test_object_wire_object_identity(self):
        tc = ToolCall("delete_email", {"id": 1}, "s", "c", effect="email:send", meta={"k": "v"})
        self.assertEqual(toolcall_from_wire(toolcall_to_wire(tc)), tc)

    def test_wire_object_wire_identity(self):
        d = {"tool_name": "t", "args": {"a": 1}, "session_id": "s",
             "call_id": "c", "effect": None, "meta": {}}
        self.assertEqual(toolcall_to_wire(toolcall_from_wire(d)), d)

    def test_missing_field_raises(self):
        with self.assertRaises(WireError):
            toolcall_from_wire({"args": {}, "session_id": "s", "call_id": "c"})

    def test_wrong_type_raises(self):
        with self.assertRaises(WireError):
            toolcall_from_wire({"tool_name": "t", "args": "not-a-dict",
                                "session_id": "s", "call_id": "c"})


class TestVerdictWire(unittest.TestCase):
    def test_plain_verdict_object_wire_object_identity(self):
        v = Verdict(Decision.ALLOW, "ok", grant_id="g1")
        self.assertEqual(verdict_from_wire(verdict_to_wire(v)), v)

    def test_hold_with_elevation_wire_object_wire_identity(self):
        d = {"decision": "hold", "reason": "held", "modified_args": None, "grant_id": None,
             "elevation": {"capability": "email:send", "scope": {"id": 1},
                           "reason": "needs elevation", "call_id": "c"}}
        self.assertEqual(verdict_to_wire(verdict_from_wire(d)), d)

    def test_decision_serializes_as_string_value_not_enum_repr(self):
        w = verdict_to_wire(Verdict(Decision.HOLD, "r"))
        self.assertEqual(w["decision"], "hold")
        self.assertIsInstance(w["decision"], str)
        self.assertNotIn("Decision", w["decision"])  # never "Decision.HOLD"
        json.dumps(w)  # must serialize with no default= fallback

    def test_elevation_references_call_by_id_only(self):
        call = ToolCall("delete_email", {"id": 9}, "sess", "call-42")
        v = Verdict(Decision.HOLD, "r",
                    elevation=ElevationRequest(call, "email:send", {"id": 9}, "why"))
        elev = verdict_to_wire(v)["elevation"]
        self.assertEqual(elev["call_id"], "call-42")
        self.assertNotIn("call", elev)       # not the nested ToolCall
        self.assertNotIn("args", elev)

    # -- malformed elevation must raise WireError, never KeyError/TypeError --
    #
    # Callers are told WireError is the one exception to expect. A raw KeyError
    # escaping from here would sail past a `except WireError` guard, and in a
    # harness that swallows hook exceptions and proceeds (Hermes does exactly
    # this) an unexpected exception type is an ALLOW. The exception type is a
    # fail-closed property, not a cosmetic one.

    def test_elevation_missing_required_field_raises_wire_error(self):
        for missing in ("capability", "scope", "reason", "call_id"):
            elevation = {"capability": "email:delete", "scope": {"id": 1},
                         "reason": "why", "call_id": "c"}
            del elevation[missing]
            with self.subTest(missing=missing):
                with self.assertRaises(WireError):
                    verdict_from_wire({"decision": "hold", "reason": "r",
                                       "elevation": elevation})

    def test_elevation_with_wrong_field_types_raises_wire_error(self):
        bad = [
            {"capability": 1, "scope": {}, "reason": "r", "call_id": "c"},
            {"capability": "c", "scope": "not-a-dict", "reason": "r", "call_id": "c"},
            {"capability": "c", "scope": {}, "reason": None, "call_id": "c"},
            {"capability": "c", "scope": {}, "reason": "r", "call_id": 42},
        ]
        for elevation in bad:
            with self.subTest(elevation=elevation):
                with self.assertRaises(WireError):
                    verdict_from_wire({"decision": "hold", "elevation": elevation})

    def test_elevation_that_is_not_an_object_raises_wire_error(self):
        for elevation in ("string", 7, ["a"], True):
            with self.subTest(elevation=elevation):
                with self.assertRaises(WireError):
                    verdict_from_wire({"decision": "hold", "elevation": elevation})

    def test_null_elevation_is_still_fine(self):
        v = verdict_from_wire({"decision": "deny", "reason": "r", "elevation": None})
        self.assertIsNone(v.elevation)
        self.assertEqual(v.decision, Decision.DENY)


class TestEnvelope(unittest.TestCase):
    def test_request_and_response_carry_schema_version(self):
        req = wrap_request(ToolCall("t", {}, "s", "c"))
        res = wrap_response(Verdict(Decision.ALLOW, "ok"))
        self.assertEqual(req["schema_version"], SCHEMA_VERSION)
        self.assertEqual(res["schema_version"], SCHEMA_VERSION)
        self.assertIn("tool_call", req)
        self.assertIn("verdict", res)


if __name__ == "__main__":
    unittest.main()
