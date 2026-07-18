"""P0 type contract tests."""

import dataclasses
import unittest

from interlock.types import (
    Decision,
    ToolCall,
    Grant,
    ElevationRequest,
    Verdict,
    FilterResult,
    PDP_UNAVAILABLE_REASON,
    GRANT_OPEN,
    GRANT_CONSUMED,
    GRANT_EXPIRED,
    GRANT_REVOKED,
)


class TestDecision(unittest.TestCase):
    def test_verdict_vocabulary_present(self):
        for name in ("ALLOW", "DENY", "HOLD", "MODIFY"):
            self.assertIn(name, Decision.__members__)

    def test_pass_is_filter_only_member(self):
        # PASS exists on the shared enum but is a filter-only outcome.
        self.assertEqual(Decision.PASS.value, "pass")


class TestToolCall(unittest.TestCase):
    def test_defaults(self):
        c = ToolCall(tool_name="list_inbox", args={}, session_id="s", call_id="c")
        self.assertIsNone(c.effect)
        self.assertEqual(c.meta, {})

    def test_frozen(self):
        c = ToolCall(tool_name="t", args={}, session_id="s", call_id="c")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            c.tool_name = "other"  # type: ignore[misc]

    def test_effect_is_only_a_hint_field(self):
        # The field exists but carries no authority; PDP re-resolves it (invariant #4).
        c = ToolCall(tool_name="t", args={}, session_id="s", call_id="c", effect="read")
        self.assertEqual(c.effect, "read")


class TestGrant(unittest.TestCase):
    def test_round_trips_through_asdict(self):
        g = Grant(
            grant_id="g1",
            capability="email:send",
            scope={"id": 123},
            uses_left=1,
            expires_at=None,
            granted_by="dennis",
            granted_at=1000.0,
            status=GRANT_OPEN,
        )
        d = dataclasses.asdict(g)
        self.assertEqual(Grant(**d), g)

    def test_status_constants_distinct(self):
        self.assertEqual(
            len({GRANT_OPEN, GRANT_CONSUMED, GRANT_EXPIRED, GRANT_REVOKED}), 4
        )


class TestVerdictAndFilterResult(unittest.TestCase):
    def test_same_field_shape(self):
        vfields = [f.name for f in dataclasses.fields(Verdict)]
        ffields = [f.name for f in dataclasses.fields(FilterResult)]
        self.assertEqual(vfields, ffields)

    def test_verdict_defaults(self):
        v = Verdict(decision=Decision.ALLOW, reason="ok")
        self.assertIsNone(v.modified_args)
        self.assertIsNone(v.grant_id)
        self.assertIsNone(v.elevation)

    def test_elevation_request_carries_the_call(self):
        c = ToolCall(tool_name="delete_email", args={"id": 1}, session_id="s", call_id="c")
        req = ElevationRequest(call=c, capability="email:send", scope={"id": 1}, reason="no grant")
        v = Verdict(decision=Decision.HOLD, reason="held", elevation=req)
        self.assertIs(v.elevation.call, c)


class TestFailClosedContract(unittest.TestCase):
    def test_reserved_reason_exists(self):
        # The fail-closed outcome is a normal DENY carrying this reason.
        self.assertEqual(PDP_UNAVAILABLE_REASON, "pdp_unavailable")


if __name__ == "__main__":
    unittest.main()
