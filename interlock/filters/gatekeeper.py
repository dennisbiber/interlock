"""
interlock.filters.gatekeeper — the sudo filter (§6).

    passive effect (read-only / reversible)      -> PASS
    consequential effect:
        grant found via find_and_consume         -> ALLOW  (grant_id recorded)
        no grant, elevation configured           -> HOLD   (ElevationRequest attached)
        no grant, no elevation                   -> DENY

The GateKeeper only consumes grants, through the consume-only view on the
context (defense-in-depth; the real boundary is the process/wire edge).
Classification and scope come from the read-only policy view, so the gate never
trusts an adapter-supplied effect hint (invariant #4 is already enforced
upstream in the pipeline).
"""

from __future__ import annotations

from interlock.types import ToolCall, FilterResult, Decision, ElevationRequest
from interlock.filters.base import FilterContext


class GateKeeper:
    name = "GateKeeper"
    consumes = True  # spends a grant on the consequential path -> must run last

    def evaluate(self, call: ToolCall, ctx: FilterContext) -> FilterResult:
        effect, is_passive = ctx.policy.classify(call.tool_name)
        if is_passive:
            return FilterResult(Decision.PASS, f"passive effect: {effect}")

        scope = ctx.policy.project_scope(call.tool_name, call.args)
        grant = ctx.ledger.find_and_consume(effect, scope)
        if grant is not None:
            return FilterResult(
                Decision.ALLOW,
                f"grant {grant.grant_id} consumed for {effect}",
                grant_id=grant.grant_id,
            )

        authorizer = ctx.policy.elevation_for(effect)
        if authorizer is not None:
            req = ElevationRequest(
                call=call,
                capability=effect,
                scope=scope,
                reason=f"consequential effect '{effect}' requires elevation",
            )
            return FilterResult(Decision.HOLD, req.reason, elevation=req)

        return FilterResult(
            Decision.DENY,
            f"consequential effect '{effect}' has no grant and no elevation configured",
        )
