"""P0 GrantLedger tests — the invariants the plan calls out plus atomicity proof."""

import concurrent.futures
import tempfile
import threading
import unittest
from unittest import mock

from interlock.ledger import GrantLedger, GRANTS_KEY
from interlock.store.state_store import StateStore
from interlock.store.session_store import SessionStore
from interlock.types import (
    GRANT_OPEN,
    GRANT_CONSUMED,
    GRANT_EXPIRED,
    GRANT_REVOKED,
)

CAP = "email:send"


def make_ledger():
    return GrantLedger(StateStore(), threading.Lock())


class TestMintAndConsume(unittest.TestCase):
    def test_mint_creates_open_single_use_grant(self):
        ledger = make_ledger()
        g = ledger.mint(CAP, {"id": 1}, uses=1, ttl=120, granted_by="dennis")
        self.assertEqual(g.status, GRANT_OPEN)
        self.assertEqual(g.uses_left, 1)
        self.assertEqual(g.capability, CAP)
        self.assertEqual(g.scope, {"id": 1})
        self.assertEqual(ledger.all()[0].grant_id, g.grant_id)

    def test_find_and_consume_success_marks_consumed(self):
        ledger = make_ledger()
        minted = ledger.mint(CAP, {"id": 1}, uses=1, ttl=120, granted_by="dennis")
        got = ledger.find_and_consume(CAP, {"id": 1})
        self.assertIsNotNone(got)
        self.assertEqual(got.grant_id, minted.grant_id)
        self.assertEqual(got.status, GRANT_CONSUMED)
        self.assertEqual(got.uses_left, 0)

    def test_mint_copies_scope_dict(self):
        ledger = make_ledger()
        scope = {"id": 1}
        ledger.mint(CAP, scope, uses=1, ttl=None, granted_by="dennis")
        scope["id"] = 999  # mutate caller's dict after minting
        self.assertIsNotNone(ledger.find_and_consume(CAP, {"id": 1}))


class TestDoubleSpend(unittest.TestCase):
    def test_single_use_cannot_be_spent_twice(self):
        ledger = make_ledger()
        ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        first = ledger.find_and_consume(CAP, {"id": 1})
        second = ledger.find_and_consume(CAP, {"id": 1})
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_concurrent_consumers_yield_exactly_one_success(self):
        # The atomicity proof: N threads race for one single-use grant; the lock
        # must let exactly one win (invariant #2, no TOCTOU double-spend).
        ledger = make_ledger()
        ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")

        n = 64
        barrier = threading.Barrier(n)

        def worker():
            barrier.wait()  # maximize contention: everyone starts together
            return ledger.find_and_consume(CAP, {"id": 1})

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
            results = [f.result() for f in [ex.submit(worker) for _ in range(n)]]

        successes = [r for r in results if r is not None]
        self.assertEqual(len(successes), 1)
        self.assertEqual(ledger.all()[0].status, GRANT_CONSUMED)


class TestExpiry(unittest.TestCase):
    def test_expired_grant_is_not_consumable(self):
        ledger = make_ledger()
        with mock.patch("interlock.ledger._now", return_value=1000.0):
            ledger.mint(CAP, {"id": 1}, uses=1, ttl=60, granted_by="dennis")  # expires 1060
        with mock.patch("interlock.ledger._now", return_value=1061.0):
            self.assertIsNone(ledger.find_and_consume(CAP, {"id": 1}))
            self.assertEqual(ledger.all()[0].status, GRANT_EXPIRED)

    def test_grant_valid_before_expiry(self):
        ledger = make_ledger()
        with mock.patch("interlock.ledger._now", return_value=1000.0):
            ledger.mint(CAP, {"id": 1}, uses=1, ttl=60, granted_by="dennis")
        with mock.patch("interlock.ledger._now", return_value=1059.0):
            self.assertIsNotNone(ledger.find_and_consume(CAP, {"id": 1}))

    def test_ttl_none_never_expires(self):
        ledger = make_ledger()
        with mock.patch("interlock.ledger._now", return_value=1000.0):
            ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        with mock.patch("interlock.ledger._now", return_value=10_000_000.0):
            self.assertIsNotNone(ledger.find_and_consume(CAP, {"id": 1}))


class TestRevoke(unittest.TestCase):
    def test_revoked_grant_is_not_consumable(self):
        ledger = make_ledger()
        g = ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        ledger.revoke(g.grant_id)
        self.assertIsNone(ledger.find_and_consume(CAP, {"id": 1}))
        self.assertEqual(ledger.all()[0].status, GRANT_REVOKED)

    def test_revoke_unknown_id_is_noop(self):
        ledger = make_ledger()
        ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        ledger.revoke("does-not-exist")  # must not raise
        self.assertIsNotNone(ledger.find_and_consume(CAP, {"id": 1}))

    def test_revoke_does_not_resurrect_consumed(self):
        ledger = make_ledger()
        g = ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        ledger.find_and_consume(CAP, {"id": 1})
        ledger.revoke(g.grant_id)  # already CONSUMED -> stays CONSUMED
        self.assertEqual(ledger.all()[0].status, GRANT_CONSUMED)


class TestMatching(unittest.TestCase):
    def test_scope_exact_match_required(self):
        ledger = make_ledger()
        ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        self.assertIsNone(ledger.find_and_consume(CAP, {"id": 2}))
        self.assertIsNone(ledger.find_and_consume(CAP, {"id": 1, "extra": True}))
        self.assertIsNotNone(ledger.find_and_consume(CAP, {"id": 1}))

    def test_capability_must_match(self):
        ledger = make_ledger()
        ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
        self.assertIsNone(ledger.find_and_consume("fs:delete", {"id": 1}))


class TestSelectionOrder(unittest.TestCase):
    def test_soonest_expiry_spent_first(self):
        ledger = make_ledger()
        with mock.patch("interlock.ledger._now", return_value=1000.0):
            long_g = ledger.mint(CAP, {"id": 1}, uses=1, ttl=100, granted_by="d")   # exp 1100
            short_g = ledger.mint(CAP, {"id": 1}, uses=1, ttl=50, granted_by="d")   # exp 1050
            first = ledger.find_and_consume(CAP, {"id": 1})
            second = ledger.find_and_consume(CAP, {"id": 1})
            third = ledger.find_and_consume(CAP, {"id": 1})
        self.assertEqual(first.grant_id, short_g.grant_id)
        self.assertEqual(second.grant_id, long_g.grant_id)
        self.assertIsNone(third)

    def test_fifo_tiebreak_when_expiry_equal(self):
        ledger = make_ledger()
        with mock.patch("interlock.ledger._now", return_value=1000.0):
            first_minted = ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="d")
        with mock.patch("interlock.ledger._now", return_value=1001.0):
            ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="d")
        got = ledger.find_and_consume(CAP, {"id": 1})
        self.assertEqual(got.grant_id, first_minted.grant_id)


class TestPersistence(unittest.TestCase):
    def test_open_grant_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            sessions = SessionStore(session_dir=d)
            ledger1 = GrantLedger(StateStore(), threading.Lock(), sessions=sessions)
            minted = ledger1.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")

            # Simulate a process restart: brand-new store + ledger, same session dir.
            ledger2 = GrantLedger(StateStore(), threading.Lock(), sessions=sessions)
            reloaded = ledger2.all()
            self.assertEqual(len(reloaded), 1)
            self.assertEqual(reloaded[0].grant_id, minted.grant_id)
            self.assertEqual(reloaded[0].status, GRANT_OPEN)

            # And it is still spendable exactly once across the restart.
            self.assertIsNotNone(ledger2.find_and_consume(CAP, {"id": 1}))

            ledger3 = GrantLedger(StateStore(), threading.Lock(), sessions=sessions)
            self.assertEqual(ledger3.all()[0].status, GRANT_CONSUMED)
            self.assertIsNone(ledger3.find_and_consume(CAP, {"id": 1}))

    def test_grants_persisted_as_plain_dicts(self):
        # SessionStore._json_safe must never meet a dataclass: what we store is dicts.
        with tempfile.TemporaryDirectory() as d:
            sessions = SessionStore(session_dir=d)
            store = StateStore()
            ledger = GrantLedger(store, threading.Lock(), sessions=sessions)
            ledger.mint(CAP, {"id": 1}, uses=1, ttl=None, granted_by="dennis")
            raw = store.get(GRANTS_KEY)
            self.assertIsInstance(raw, list)
            self.assertIsInstance(raw[0], dict)


if __name__ == "__main__":
    unittest.main()
