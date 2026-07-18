"""
interlock.wire — the FROZEN wire schema (P4).

This is the single serialization chokepoint between the PDP and any PEP. The
envelope carries schema_version at the top level so a version mismatch fails
closed (the service denies rather than parsing an unknown format).

Nothing here lets an enum or a dataclass reach json.dumps: `decision` is written
as its string value, and objects are converted field-by-field. We deliberately
do NOT lean on json.dumps(default=str) as a safety net — it would stringify
Decision.HOLD to the literal "Decision.HOLD", a silent corruption. If a value
can't be represented as plain JSON here, that's a bug to fix here, not to paper
over downstream.

Request envelope:
    { "schema_version": 1, "tool_call": { ...ToolCall fields... } }
Response envelope:
    { "schema_version": 1, "verdict": { ...Verdict fields... } }

The wire `elevation` references the originating call by call_id only (the PEP
still holds the call it sent and correlates on call_id); it does NOT re-embed the
full ToolCall. Round-tripping a HOLD-with-elevation through the wire is therefore
lossy on that nested call by design — wire->object->wire is identity, but
object->wire->object drops the nested call's non-id fields.
"""

from __future__ import annotations

from interlock.types import ToolCall, Verdict, Decision, ElevationRequest

SCHEMA_VERSION = 1


class WireError(ValueError):
    """Raised when an incoming payload is not a valid wire object."""


# --- field validators ------------------------------------------------------

def _req_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str):
        raise WireError(f"field {key!r} must be a string")
    return v


def _req_dict(d: dict, key: str) -> dict:
    v = d.get(key)
    if not isinstance(v, dict):
        raise WireError(f"field {key!r} must be an object")
    return v


# --- ToolCall <-> wire ------------------------------------------------------

def toolcall_to_wire(call: ToolCall) -> dict:
    return {
        "tool_name": call.tool_name,
        "args": call.args,
        "session_id": call.session_id,
        "call_id": call.call_id,
        "effect": call.effect,
        "meta": call.meta,
    }


def toolcall_from_wire(d: dict) -> ToolCall:
    if not isinstance(d, dict):
        raise WireError("tool_call must be an object")
    effect = d.get("effect")
    if effect is not None and not isinstance(effect, str):
        raise WireError("field 'effect' must be a string or null")
    meta = d.get("meta")
    if meta is None:
        meta = {}
    elif not isinstance(meta, dict):
        raise WireError("field 'meta' must be an object")
    return ToolCall(
        tool_name=_req_str(d, "tool_name"),
        args=_req_dict(d, "args"),
        session_id=_req_str(d, "session_id"),
        call_id=_req_str(d, "call_id"),
        effect=effect,
        meta=meta,
    )


# --- Verdict <-> wire -------------------------------------------------------

def verdict_to_wire(v: Verdict) -> dict:
    elevation = None
    if v.elevation is not None:
        elevation = {
            "capability": v.elevation.capability,
            "scope": v.elevation.scope,
            "reason": v.elevation.reason,
            "call_id": v.elevation.call.call_id,   # reference, not the nested call
        }
    return {
        "decision": v.decision.value,   # string value, never the enum object
        "reason": v.reason,
        "modified_args": v.modified_args,
        "grant_id": v.grant_id,
        "elevation": elevation,
    }


def verdict_from_wire(d: dict) -> Verdict:
    if not isinstance(d, dict):
        raise WireError("verdict must be an object")
    elevation = None
    e = d.get("elevation")
    if e is not None:
        # Reconstruct a lightweight ElevationRequest; the nested call carries
        # only the call_id (the wire never had the rest).
        #
        # Every field is validated rather than indexed raw. A malformed
        # elevation must surface as WireError — the one exception type callers
        # are told to expect — so a fail-closed PEP catching WireError cannot be
        # bypassed by a KeyError/TypeError escaping from here into a caller that
        # treats an unexpected exception differently.
        if not isinstance(e, dict):
            raise WireError("field 'elevation' must be an object or null")
        elevation = ElevationRequest(
            call=ToolCall(
                tool_name="", args={}, session_id="", call_id=_req_str(e, "call_id")
            ),
            capability=_req_str(e, "capability"),
            scope=_req_dict(e, "scope"),
            reason=_req_str(e, "reason"),
        )
    try:
        decision = Decision(d["decision"])
    except (KeyError, ValueError) as exc:
        raise WireError(f"invalid decision: {d.get('decision')!r}") from exc
    return Verdict(
        decision=decision,
        reason=d.get("reason", ""),
        modified_args=d.get("modified_args"),
        grant_id=d.get("grant_id"),
        elevation=elevation,
    )


# --- envelopes --------------------------------------------------------------

def wrap_request(call: ToolCall) -> dict:
    return {"schema_version": SCHEMA_VERSION, "tool_call": toolcall_to_wire(call)}


def wrap_response(verdict: Verdict) -> dict:
    return {"schema_version": SCHEMA_VERSION, "verdict": verdict_to_wire(verdict)}
