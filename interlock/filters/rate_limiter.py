"""
interlock.filters.rate_limiter — a fixed-window rate limiter (§10).

A non-consuming filter (consumes = False), so the ordering assertion forces it
BEFORE GateKeeper. Over the limit -> DENY, which short-circuits before the gate
consumes, so no grant is ever burned on a throttled call.

HARD-CEILING SEMANTIC — counts ATTEMPTS, not approved actions. Because the
limiter runs before elevation, EVERY attempt at a consequential effect consumes
budget, including attempts later denied or rejected at elevation. A per-effect
limit of N therefore means "no more than N attempts of this effect per window,
no matter the outcome or who approves" — the intended runaway throttle, which
caps even human-approved actions. GateKeeper + single-use grants are the primary
runaway stop, so the default is `null` (unlimited): operators opt IN to a hard
cap on specific high-risk effects; nothing is silently capped. (A post-elevation
"N approved actions" cap — counting only successful actions via a limit
inside/after elevation — is a different design, explicitly deferred past v1.)

Idempotent across re-runs: _resolve_hold re-runs the whole chain after a grant is
minted, so a naive per-evaluate counter would count one attempt twice. We dedupe
on call_id — a call_id already counted in the current window PASSes without
re-incrementing — so one logical attempt counts once whether the chain runs once
or twice. (This dedupe is about the internal re-run, not about the attempts
semantic above: two DIFFERENT call_ids are two attempts.)

Thread-safety: all window-state reads and mutations (roll + dedupe-check +
count-check + increment) run under a per-instance lock as ONE atomic critical
section, so concurrent evaluate() calls (P4 serves one shared instance) can't
race check-then-increment. Same discipline as the ledger's find_and_consume.

Window state is in-memory and NOT persisted (a restart resetting the window is
acceptable). Time is indirected through _now so tests can patch the clock.

Passive effects are never limited (classified via the policy view).
"""

from __future__ import annotations

import threading
import time

from interlock.types import ToolCall, FilterResult, Decision, RATE_LIMITED_REASON
from interlock.filters.base import FilterContext

KEY_MODES = ("session", "session_effect")


def _now() -> float:
    return time.time()


class RateLimiter:
    name = "RateLimiter"
    consumes = False  # must run before consuming filters

    def __init__(self, config: dict | None = None):
        config = config or {}
        key = config.get("key", "session_effect")
        if key not in KEY_MODES:
            raise ValueError(
                f"rate_limits.key must be one of {KEY_MODES!r}, got {key!r}"
            )
        self._key_mode = key
        self._window = float(config.get("window_seconds", 3600))
        self._default = config.get("default", None)      # None => unlimited
        self._per_effect = dict(config.get("per_effect", {}))

        # In-memory window state, guarded by _lock so the whole
        # roll+dedupe+check+increment sequence is one atomic critical section.
        self._lock = threading.Lock()
        self._window_start = _now()
        self._counts: dict[tuple, int] = {}
        self._seen: set[str] = set()

    def evaluate(self, call: ToolCall, ctx: FilterContext) -> FilterResult:
        effect, is_passive = ctx.policy.classify(call.tool_name)
        if is_passive:
            return FilterResult(Decision.PASS, "passive effect not rate-limited")

        limit = self._per_effect.get(effect, self._default)
        if limit is None:
            return FilterResult(Decision.PASS, "no rate limit configured")

        # One atomic critical section: roll + dedupe-check + count-check +
        # increment. classify() and the limit lookup above touch only read-only
        # config, so they stay outside the lock.
        with self._lock:
            self._roll_window()

            # Dedupe: the _resolve_hold re-run carries the same call_id; count once.
            if call.call_id in self._seen:
                return FilterResult(Decision.PASS, "call_id already counted this window")

            key = self._key(call, effect)
            if self._counts.get(key, 0) >= limit:
                return FilterResult(Decision.DENY, RATE_LIMITED_REASON)

            self._counts[key] = self._counts.get(key, 0) + 1
            self._seen.add(call.call_id)
            return FilterResult(Decision.PASS, "within rate limit")

    # ------------------------------------------------------------------

    def _roll_window(self) -> None:
        now = _now()
        if now - self._window_start >= self._window:
            self._window_start = now
            self._counts = {}
            self._seen = set()

    def _key(self, call: ToolCall, effect: str) -> tuple:
        if self._key_mode == "session_effect":
            return (call.session_id, effect)
        return (call.session_id,)
