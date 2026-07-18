"""
interlock.types — core, dumb, serializable data types for the PDP.

These are the frozen contract that the P4 wire schema serializes (as asdict /
JSON). Keep them free of behavior and free of any harness/framework import.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Fail-closed contract (fifth invariant)
# ---------------------------------------------------------------------------
# The PEP must fail CLOSED when it cannot reach the PDP or the call times out:
# it BLOCKS the tool rather than allowing it. On the wire that outcome is an
# ordinary Decision.DENY carrying this reserved reason, so the audit log can
# tell an availability failure apart from a genuine policy denial. The
# deny-on-error path itself lives in the P5 adapter; the contract names it here
# from P0 so nothing downstream has to invent an ad-hoc string later.
PDP_UNAVAILABLE_REASON = "pdp_unavailable"

# Reserved DENY reason emitted by RateLimiter, so audit/metrics can distinguish a
# throttle from a policy denial by exact string match. Used verbatim as the
# Verdict reason (the throttled effect is captured separately in the audit
# record's `effect` field).
RATE_LIMITED_REASON = "rate_limited"

# Reserved service-side DENY reasons (P4). The PDP service answers a well-formed
# request only with a Verdict; these let it fail CLOSED on bad input or internal
# error without ever returning ALLOW-by-omission (or a 5xx a PEP might misread).
MALFORMED_REQUEST_REASON = "malformed_request"    # unparseable / schema-invalid body
UNSUPPORTED_SCHEMA_REASON = "unsupported_schema"   # schema_version the service doesn't support
PDP_ERROR_REASON = "pdp_error"                     # unexpected handler exception, mapped to DENY

# ---------------------------------------------------------------------------
# Grant status values (kept as plain strings so SessionStore's JSON persistence
# never has to serialize an enum; see interlock.ledger).
# ---------------------------------------------------------------------------
GRANT_OPEN = "OPEN"
GRANT_CONSUMED = "CONSUMED"
GRANT_EXPIRED = "EXPIRED"
GRANT_REVOKED = "REVOKED"


class Decision(Enum):
    """
    Outcome vocabulary.

    ALLOW / DENY / HOLD / MODIFY are the four the plan (§3) lists for a final
    Verdict. PASS is a *filter-only* outcome from §5 ("no objection, continue")
    that must never appear in a final Verdict — the pipeline resolves an
    all-PASS chain to ALLOW. It lives on the same enum so FilterResult and
    Verdict keep the identical shape the plan calls for; "PASS is filter-only"
    is a pipeline invariant enforced in P1, not a type-level constraint.
    """

    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"
    MODIFY = "modify"
    PASS = "pass"


@dataclass(frozen=True)
class ToolCall:
    """
    A normalized tool-execution request — the 'syscall' the PDP evaluates.

    `effect` is at most an adapter-supplied HINT. The PDP re-resolves the
    authoritative effect from policy before any filter runs (invariant #4), so a
    harness can never talk itself into the passive lane by setting this.
    """

    tool_name: str
    args: dict
    session_id: str
    call_id: str
    effect: str | None = None
    meta: dict = field(default_factory=dict)


@dataclass
class Grant:
    """
    One capability token in the ledger.

    Non-frozen because status / uses_left settle over the grant's life. In v1
    every grant is single-use (uses_left starts at 1) and item-scoped, so it
    authorizes exactly one action on exactly one item and then is gone.

    `scope` keys must be JSON-object-safe (strings), because the ledger persists
    grants through SessionStore's JSON layer and matches scope by exact equality.
    """

    grant_id: str
    capability: str          # matches the PDP-resolved ToolCall.effect (or a specific tool_name)
    scope: dict              # exact-match constraints, e.g. {"id": 123}
    uses_left: int           # v1: always 1
    expires_at: float | None  # epoch seconds; None = no time-box
    granted_by: str          # human id or policy name
    granted_at: float
    status: str              # one of GRANT_OPEN | GRANT_CONSUMED | GRANT_EXPIRED | GRANT_REVOKED


@dataclass(frozen=True)
class ElevationRequest:
    """
    What the pipeline hands an Authorizer when the gate returns HOLD (§7):
    exactly what is being asked for, so a human or policy can decide. Authorizers
    arrive in P2; this type is defined in P0 because Verdict references it.
    """

    call: ToolCall
    capability: str
    scope: dict
    reason: str


@dataclass(frozen=True)
class Verdict:
    """The PDP's single composed answer for one ToolCall."""

    decision: Decision
    reason: str
    modified_args: dict | None = None            # populated only by MODIFY (deferred past v1)
    grant_id: str | None = None                  # the grant consumed to ALLOW, if any
    elevation: ElevationRequest | None = None    # populated on HOLD


@dataclass(frozen=True)
class FilterResult:
    """
    One filter's opinion — the per-filter analogue of Verdict, same shape (§5).
    A filter voices "no objection, continue" with Decision.PASS.
    """

    decision: Decision
    reason: str
    modified_args: dict | None = None
    grant_id: str | None = None
    elevation: ElevationRequest | None = None
