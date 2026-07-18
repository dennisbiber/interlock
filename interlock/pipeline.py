"""
interlock.pipeline — the PDP core.

Two pieces:

  Policy          — loads policy.json and resolves effects authoritatively.
                    Default-deny by effect: a tool is passive only if it is
                    mapped to an effect listed in passive_effects; everything
                    else — explicitly consequential OR simply unclassified — is
                    consequential and gated (invariant #4). consequential_effects
                    is documentation/validation only; it plays no part in the
                    decision, because "not passive" already means "gated".

  FilterPipeline  — resolves the effect at entry (before any filter runs),
                    then runs the filter chain with most-restrictive-wins
                    composition and short-circuit on DENY.

Composition (§5): run filters in order. DENY ends immediately. HOLD is
remembered (first one wins) and becomes the verdict unless a later filter DENYs.
MODIFY accumulates arg transforms. PASS/ALLOW continue. Severity order is
DENY > HOLD > MODIFY > ALLOW.

Ordering constraint (now enforced at construction): a grant-consuming filter
(any filter with `consumes = True`, e.g. GateKeeper) must run AFTER every
non-consuming filter, so a grant is never spent on a call a later filter would
deny or hold. FilterPipeline.__init__ raises if that ordering is violated.

Single process (invariant #6): the pipeline shares the ledger's in-process lock;
correctness of atomic consumption assumes one PDP process. See ledger.py.

Wired in P2:
  * kill-flag emergency stop, checked FIRST in evaluate()
  * HOLD resolution via an Authorizer (synchronous handshake)
Still later:
  * audit sink                                (P3)
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Optional

from interlock.types import ToolCall, Verdict, Decision
from interlock.ledger import GrantLedger, ConsumeOnlyView, _now
from interlock.filters.base import Filter, FilterContext

logger = logging.getLogger("interlock.pipeline")


class Policy:
    """Read-only policy config. Implements the PolicyView protocol structurally."""

    def __init__(self, data: dict):
        self._default_posture = data.get("default_posture", "deny")
        self._passive = set(data.get("passive_effects", []))
        self._consequential = set(data.get("consequential_effects", []))
        self._tool_effects = dict(data.get("tool_effects", {}))
        self._tool_scopes = dict(data.get("tool_scopes", {}))
        self._elevation = dict(data.get("elevation", {}))
        self._filters = list(data.get("filters", []))
        self._rate_limits = dict(data.get("rate_limits", {}))

    @classmethod
    def from_file(cls, path) -> "Policy":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        return cls(data)

    def classify(self, tool_name: str) -> tuple[str, bool]:
        """
        Return (resolved_effect, is_passive).

        A tool is passive ONLY if it is explicitly mapped to an effect that is in
        passive_effects. An unmapped tool is never passive (its effect identity
        is its own name) — so forgetting to classify fails safe.
        """
        mapped = self._tool_effects.get(tool_name)
        if mapped is not None and mapped in self._passive:
            return (mapped, True)
        if mapped is not None:
            return (mapped, False)
        return (tool_name, False)

    def project_scope(self, tool_name: str, args: dict) -> dict:
        """Project only the policy-declared stable identifying args (never the raw blob)."""
        keys = self._tool_scopes.get(tool_name, [])
        return {k: args[k] for k in keys if k in args}

    def elevation_for(self, effect: str) -> Optional[str]:
        """Effect-specific authorizer name, else the default, else None (=> DENY)."""
        return self._elevation.get(effect, self._elevation.get("default"))

    @property
    def filter_order(self) -> list:
        """Declarative intended filter order (a construction factory reads this later)."""
        return list(self._filters)

    def rate_limit_config(self) -> dict:
        """Raw rate-limit config for constructing a RateLimiter."""
        return dict(self._rate_limits)


class FilterPipeline:
    """
    The harness-agnostic PDP. `ledger` is the full (mint-capable) GrantLedger,
    used to derive the consume-only view handed to filters; the pipeline itself
    never calls mint. `authorizer` (P2) and `audit` (P3) are accepted now for a
    stable signature and are inert until their phases.
    """

    def __init__(self, filters, ledger: GrantLedger, policy: Policy,
                 authorizer=None, audit=None):
        self._filters: list[Filter] = list(filters)
        self._assert_consuming_filters_last(self._filters)
        self._ledger = ledger
        self._policy = policy
        self._authorizer = authorizer   # synchronous handshake (P2)
        self._audit = audit             # wired in P3
        self._consume_view = ConsumeOnlyView(ledger)

    @staticmethod
    def _assert_consuming_filters_last(filters) -> None:
        # Once a consuming filter appears, no non-consuming filter may follow it.
        # A raise (not assert) so it holds under `python -O`.
        seen_consuming = False
        for f in filters:
            consumes = getattr(f, "consumes", False)
            if seen_consuming and not consumes:
                raise ValueError(
                    f"filter ordering: non-consuming filter {getattr(f, 'name', f)!r} "
                    f"runs after a consuming filter; consuming filters must be last "
                    f"so a grant is never spent on a call a later filter denies/holds"
                )
            seen_consuming = seen_consuming or consumes

    def evaluate(self, call: ToolCall) -> Verdict:
        # Every exit path funnels through _finish so the audit sink is written
        # exactly once — including the kill-switch early return and the
        # fail-closed unknown-decision path. An audit log with holes is worse
        # than none.
        verdict, effect, handshake = self._decide(call)
        return self._finish(call, effect, verdict, handshake)

    def _decide(self, call: ToolCall):
        """Return (verdict, resolved_effect_or_None, handshake_outcome_or_None)."""
        # Emergency stop, checked FIRST: when engaged, deny everything —
        # passive reads included — before any filter or effect resolution runs.
        if self._ledger.is_killed():
            return Verdict(Decision.DENY, "kill switch engaged"), None, None

        # Invariant #4: resolve the effect authoritatively, overwriting any
        # adapter-supplied hint, BEFORE any filter runs.
        effect, _is_passive = self._policy.classify(call.tool_name)
        call = replace(call, effect=effect)

        ctx = FilterContext(ledger=self._consume_view, policy=self._policy)
        verdict = self._run_chain(call, ctx)

        # Synchronous handshake: if the chain HELD and an authorizer is wired,
        # route the elevation request to it now. In deferred mode (no
        # authorizer) the HOLD is returned as-is for the harness to resolve and
        # the agent to re-issue.
        if verdict.decision == Decision.HOLD and self._authorizer is not None:
            verdict, handshake = self._resolve_hold(verdict, call, ctx)
            return verdict, effect, handshake

        return verdict, effect, None

    def _finish(self, call: ToolCall, effect, verdict: Verdict, handshake) -> Verdict:
        # Write exactly one audit record with the FINAL verdict, then return it.
        # Wrapped so no audit failure can crash evaluate() or flip the verdict.
        if self._audit is not None:
            record = {
                "ts": _now(),
                "session_id": call.session_id,
                "call_id": call.call_id,
                "tool_name": call.tool_name,
                "effect": effect,                       # None on the kill-switch path
                "decision": verdict.decision.value,
                "reason": verdict.reason,
                "grant_id": verdict.grant_id,
                "handshake": handshake,                 # approved|denied|orphan_revoked|None
            }
            try:
                self._audit.record(record)
            except Exception:
                logger.exception("audit sink raised; verdict left unchanged")
        return verdict

    def _resolve_hold(self, verdict: Verdict, call: ToolCall, ctx: FilterContext):
        """Return (verdict, handshake_outcome)."""
        grant = self._authorizer.authorize(verdict.elevation)
        if grant is None:
            return Verdict(Decision.DENY, "elevation denied by authorizer"), "denied"
        # The authorizer minted a matching single-use grant. Re-run the chain
        # ONCE so the gate consumes it through the atomic path (never a bare
        # consume, never a double-run loop). If it STILL holds, the mint could
        # not satisfy the call (essentially unreachable in v1, since Human/Policy
        # approvers mint with the request's own capability+scope) — revoke the
        # orphan so it can't sit OPEN until TTL, then deny.
        resolved = self._run_chain(call, ctx)
        if resolved.decision == Decision.HOLD:
            self._ledger.revoke(grant.grant_id)
            return Verdict(Decision.DENY, "grant minted but call still held"), "orphan_revoked"
        return resolved, "approved"

    # ------------------------------------------------------------------

    def _run_chain(self, call: ToolCall, ctx: FilterContext) -> Verdict:
        held = None            # first HOLD FilterResult, if any
        allow_grant_id = None  # grant_id from a consuming filter's ALLOW
        modified = None        # accumulated MODIFY args

        for f in self._filters:
            r = f.evaluate(call, ctx)
            d = r.decision
            if d == Decision.DENY:
                return Verdict(Decision.DENY, r.reason)         # short-circuit
            elif d == Decision.HOLD:
                if held is None:
                    held = r
            elif d == Decision.MODIFY:
                modified = dict(modified or {})
                if r.modified_args:
                    modified.update(r.modified_args)
            elif d == Decision.ALLOW:
                if r.grant_id and allow_grant_id is None:
                    allow_grant_id = r.grant_id
            elif d == Decision.PASS:
                continue
            else:
                # Unknown outcome -> fail closed.
                return Verdict(Decision.DENY, f"unknown filter decision: {d!r}")

        if held is not None:
            return Verdict(Decision.HOLD, held.reason, elevation=held.elevation)
        if modified is not None:
            return Verdict(Decision.MODIFY, "args modified", modified_args=modified)
        return Verdict(Decision.ALLOW, "allowed", grant_id=allow_grant_id)
