"""
interlock.ledger — the GrantLedger (capability table) on top of StateStore.

Two load-bearing invariants live here:

  #2  find_and_consume is ATOMIC. Find, validate, decrement, and persist all
      happen under a single lock, so a single-use grant can never be
      double-spent — there is no TOCTOU window between check and consume.
      There is deliberately no bare `consume`.

  #3  mint() is the ONLY way a grant comes into existence, and by construction
      only an Authorizer holds a mint-capable reference. The consume-only view
      handed to filters (ConsumeOnlyView) is defense-in-depth, not a hard
      boundary — the real trust boundary is the process/wire edge, where the
      untrusted agent/harness lives. See ConsumeOnlyView for the honest limits.

  #6  SINGLE PROCESS (hard invariant, binds P4). This ledger's atomicity rests
      on an in-process threading.Lock, which serializes nothing across process
      boundaries. The PDP MUST run as a single process. If P4 ever forks workers
      or runs multiple PDP instances against the same store, the double-spend
      guarantee (#2) is void until the in-process lock is replaced by a
      cross-process mechanism (file lock, DB transaction, or a single-writer
      broker). Do not multi-process this without that replacement.

Durability. Grants are stored under a reserved key as plain dicts — never as
Grant dataclasses, because SessionStore's JSON fallback would stringify a
dataclass and silently corrupt it. When a SessionStore is supplied, the ledger
save-throughs after every mutation, so an OPEN grant awaiting approval survives
a process restart (and policy state cannot be "compacted out" of a prompt — it
lives on disk, not in the context window).

v1 scope. Grants are single-use and matched on capability + exact scope only.
session_id is recorded for audit if present but never participates in matching.
Multi-use and session-bound matching are explicit future additions; the schema
leaves room for them but no authorizer mints uses > 1 in v1.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict
from typing import Optional

from interlock.store.state_store import StateStore
from interlock.store.session_store import SessionStore
from interlock.types import (
    Grant,
    GRANT_OPEN,
    GRANT_CONSUMED,
    GRANT_EXPIRED,
    GRANT_REVOKED,
)

# Reserved key holding the grant list inside the ledger's StateStore.
GRANTS_KEY = "__grants__"
# Reserved key holding the emergency-stop flag.
KILL_KEY = "__kill__"
# SessionStore chat_id under which the ledger persists its own store.
DEFAULT_LEDGER_ID = "__grants__"


def _now() -> float:
    """Wall-clock seconds. Indirected so tests can patch time deterministically."""
    return time.time()


class ConsumeOnlyView:
    """
    A consume-only handle on a GrantLedger, handed to the filter chain.

    Defense-in-depth, NOT a security boundary. It exposes find_and_consume and
    nothing else, which keeps a filter from *casually* or *accidentally* minting
    or revoking. It is not a sandbox: the captured bound method still carries a
    __self__ back to the ledger, so a determined in-process filter could reach
    mint() by reflection. That's acceptable, because filters are trusted
    PDP-side code. The real trust boundary is the process/wire edge (invariant
    stack, #1/#6): the untrusted party is the agent/harness across the wire, and
    it never holds a Python reference to anything in this process at all.
    """

    def __init__(self, ledger: "GrantLedger"):
        self._find_and_consume = ledger.find_and_consume

    def find_and_consume(self, capability: str, scope: dict):
        return self._find_and_consume(capability, scope)


class GrantLedger:
    """
    The capability table. `store` is the live working state; `lock` guards every
    mutation; `sessions` (optional) provides durable save-through. The leading
    (store, lock) positional signature matches the plan (§6); `sessions` /
    `ledger_id` are an additive durability channel — omit them for a pure
    in-memory ledger (e.g. in unit tests that don't exercise persistence).
    """

    def __init__(
        self,
        store: StateStore,
        lock: threading.Lock,
        sessions: Optional[SessionStore] = None,
        ledger_id: str = DEFAULT_LEDGER_ID,
    ):
        self._store = store
        self._lock = lock
        self._sessions = sessions
        self._ledger_id = ledger_id
        # Seed from disk if a persistence channel is wired (survives restart).
        if self._sessions is not None:
            loaded = self._sessions.load(self._ledger_id)
            self._store.restore(loaded.snapshot())
        self._store.ensure(GRANTS_KEY, [])

    # ------------------------------------------------------------------
    # Authorizer-only path
    # ------------------------------------------------------------------

    def mint(self, capability, scope, uses, ttl, granted_by) -> Grant:
        """
        Create and persist an OPEN grant. Invariant #3: only an Authorizer ever
        calls this. `ttl` is seconds from now (None = no time-box).
        """
        with self._lock:
            now = _now()
            grant = Grant(
                grant_id=uuid.uuid4().hex,
                capability=capability,
                scope=dict(scope),
                uses_left=uses,
                expires_at=(now + ttl) if ttl is not None else None,
                granted_by=granted_by,
                granted_at=now,
                status=GRANT_OPEN,
            )
            grants = self._grants()
            grants.append(asdict(grant))
            self._commit(grants)
            return grant

    # ------------------------------------------------------------------
    # Consume path (safe to hand to the filter chain)
    # ------------------------------------------------------------------

    def find_and_consume(self, capability: str, scope: dict) -> Grant | None:
        """
        ATOMIC. The only correct way to spend a grant (invariant #2).

        Matches OPEN grants on capability + exact scope equality (no session
        match in v1). Among matches, spends the most perishable first
        (soonest-expiry, then granted_at FIFO as tiebreak). Lazily settles
        expiry. All of find -> validate -> decrement -> persist runs under one
        lock, so two concurrent callers can never both spend the same grant.
        """
        with self._lock:
            grants = self._grants()
            self._settle_expiry(grants)
            candidates = [
                g
                for g in grants
                if g["status"] == GRANT_OPEN
                and g["capability"] == capability
                and g["scope"] == scope
            ]
            if not candidates:
                # Expiry settlement above may have changed state; persist it.
                self._commit(grants)
                return None
            candidates.sort(key=self._perishability)
            chosen = candidates[0]
            chosen["uses_left"] -= 1
            if chosen["uses_left"] <= 0:
                chosen["status"] = GRANT_CONSUMED
            self._commit(grants)
            return Grant(**chosen)

    # ------------------------------------------------------------------
    # Abort / introspection
    # ------------------------------------------------------------------

    def revoke(self, grant_id: str) -> None:
        """
        Revoke an OPEN grant (idempotent no-op if unknown or already settled).
        Out-of-band abort (§7) revokes outstanding grants so the next gated call
        fails closed.
        """
        with self._lock:
            grants = self._grants()
            for g in grants:
                if g["grant_id"] == grant_id and g["status"] == GRANT_OPEN:
                    g["status"] = GRANT_REVOKED
            self._commit(grants)

    def all(self) -> list[Grant]:
        """
        All grants, for audit / introspection. Also settles (and persists) lazy
        expiry, so reported status and on-disk status never diverge.
        """
        with self._lock:
            grants = self._grants()
            self._settle_expiry(grants)
            self._commit(grants)
            return [Grant(**g) for g in grants]

    # ------------------------------------------------------------------
    # Emergency stop (§7). The pipeline checks is_killed() FIRST, before any
    # filter runs; when engaged, the PDP denies everything — passive reads
    # included. It is "unplug the machine", not a policy tweak. Persisted, so it
    # survives a restart until an operator explicitly disengages it. Operators
    # hold the full ledger; filters (consume-only view) cannot touch this.
    # ------------------------------------------------------------------

    def engage_kill_switch(self, reason: str = "") -> None:
        with self._lock:
            self._store.set(KILL_KEY, {"engaged": True, "reason": reason, "at": _now()})
            self._persist()

    def disengage_kill_switch(self) -> None:
        with self._lock:
            self._store.set(KILL_KEY, {"engaged": False})
            self._persist()

    def is_killed(self) -> bool:
        with self._lock:
            flag = self._store.get(KILL_KEY, {}) or {}
            return bool(flag.get("engaged", False))

    # ------------------------------------------------------------------
    # Internals (all callers already hold the lock)
    # ------------------------------------------------------------------

    def _grants(self) -> list:
        """Read the grant list. Written back via _commit (read-modify-write)."""
        self._store.ensure(GRANTS_KEY, [])
        return self._store.get(GRANTS_KEY, [])

    def _settle_expiry(self, grants: list) -> None:
        now = _now()
        for g in grants:
            if (
                g["status"] == GRANT_OPEN
                and g["expires_at"] is not None
                and g["expires_at"] <= now
            ):
                g["status"] = GRANT_EXPIRED

    @staticmethod
    def _perishability(g: dict):
        # Timed grants (non-None expiry) before never-expiring ones; among timed,
        # soonest expiry first; granted_at ascending as the FIFO tiebreak.
        exp = g["expires_at"]
        return (exp is None, exp if exp is not None else 0.0, g["granted_at"])

    def _commit(self, grants: list) -> None:
        # Write the grant list back (correct even for a copy-returning StateStore
        # backend), then durably save through.
        self._store.set(GRANTS_KEY, grants)
        self._persist()

    def _persist(self) -> None:
        # Durably save the whole store if a SessionStore is wired.
        if self._sessions is not None:
            self._sessions.save(self._ledger_id, self._store)
