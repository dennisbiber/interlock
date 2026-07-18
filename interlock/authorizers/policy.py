"""
interlock.authorizers.policy — the deterministic, no-human approver (§7).

PolicyApprover auto-approves ONLY when an explicit, deterministic safe rule says
so, and even then it mints a single-use grant (uses=1) — it is the no-human
path, not a multi-use exception. Anything the rule doesn't affirmatively allow
is refused (None), so a missing or unsure rule fails closed.

The rule is any callable ElevationRequest -> bool. Keep rules boring and
total: no I/O, no model calls, no ambient state — just a decision over the
request's capability/scope/args.
"""

from __future__ import annotations

from typing import Callable, Optional

from interlock.types import ElevationRequest, Grant


class PolicyApprover:
    name = "PolicyApprover"

    def __init__(self, ledger, rule: Callable[[ElevationRequest], bool],
                 ttl: Optional[float] = 120.0, granted_by: str = "policy"):
        self._ledger = ledger      # mint-capable; only authorizers hold this
        self._rule = rule
        self._ttl = ttl
        self._granted_by = granted_by

    def authorize(self, req: ElevationRequest) -> Optional[Grant]:
        if self._rule(req):
            return self._ledger.mint(
                capability=req.capability,
                scope=req.scope,
                uses=1,               # single-use, even on the auto path
                ttl=self._ttl,
                granted_by=self._granted_by,
            )
        return None
