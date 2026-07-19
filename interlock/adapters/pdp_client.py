"""
interlock.adapters.pdp_client — the harness-agnostic PYTHON PEP core (H0.1).

This is the Python counterpart of ``adapters/openclaw/pdp_client.js`` and it
mirrors that module's semantics deliberately: every Python-hosted adapter reuses
this file rather than reimplementing the security-critical path. When a harness's
API shifts, the shim moves; this does not.

FAIL CLOSED IS THE WHOLE POINT (invariant #5). Every failure mode BLOCKS:

    socket missing / connection refused / connect timeout / read timeout /
    partial read / oversized response / non-200 status / non-JSON body /
    non-object body / unrecognized schema_version / missing or malformed
    verdict / a decision string this client does not explicitly recognize /
    any unexpected exception anywhere in the path

Only an explicit ``allow`` permits. ``deny`` blocks terminally. ``hold`` blocks
and surfaces the elevation summary for out-of-band approval and re-issue.

THREE THINGS THAT LOOK LIKE STYLE BUT ARE LOAD-BEARING
------------------------------------------------------

1. **Decisions are matched as literal wire strings, never parsed through the
   ``Decision`` enum.** ``Decision("pass")`` succeeds — PASS is a valid enum
   member because filters use it internally — but PASS must never appear in a
   final Verdict. Round-tripping through the enum would turn "the PDP sent
   something structurally impossible" into a value we might then reason about.
   Matching literals means anything outside {allow, deny, hold} falls into the
   fail-closed branch by construction, including ``pass`` and (for now)
   ``modify``.

2. **``effect`` is forced to None on the way out.** The PDP re-resolves the
   authoritative effect from policy (invariant #4), so a client-supplied hint is
   at best noise and at worst an attempt to talk into the passive lane. We strip
   it here as defense in depth. The real boundary is the PDP; this just means a
   buggy shim cannot even try.

3. **This client never short-circuits.** There is no "looks passive, skip the
   round trip" path, because the PDP — not the adapter — is the authority on
   effect classification. EVERY tool call goes over the wire. A local UDS round
   trip is sub-millisecond; a client-side classification cache would be a second
   policy engine with no audit trail.

ON EXCEPTION-PROOFING
---------------------
``decide()`` is documented and tested to never raise. That is not defensive
politeness — at least one supported harness (Hermes) swallows an exception
raised by a pre-tool hook at debug level and then PROCEEDS to execute the tool.
In that harness, an exception escaping this module is an ALLOW. So the outermost
handler catches ``Exception`` broadly and converts it into a block. The
conformance battery asserts this with a deliberately induced internal fault.
"""

from __future__ import annotations

import http.client
import json
import socket
from dataclasses import dataclass
from typing import Optional

from interlock.types import PDP_UNAVAILABLE_REASON, ToolCall
from interlock.wire import SCHEMA_VERSION, toolcall_to_wire

__all__ = [
    "PdpClient",
    "PdpUnavailable",
    "PepOutcome",
    "decide",
    "hold_summary",
    "DEFAULT_TIMEOUT",
    "MAX_RESPONSE_BYTES",
]

# Short by design: a hung PDP must not hang the agent. Matches the JS client's
# 2000ms default so both languages behave identically under a stalled service.
DEFAULT_TIMEOUT = 2.0

# A well-formed verdict is a few hundred bytes. This bound exists so a broken or
# hostile responder cannot make the PEP read unboundedly; exceeding it fails
# closed like any other transport fault.
MAX_RESPONSE_BYTES = 1 << 20  # 1 MiB

_EVALUATE_PATH = "/evaluate"

# The only decision strings this client acts on. Everything else — including the
# filter-internal "pass" and the not-yet-implemented "modify" — fails closed.
_ALLOW = "allow"
_DENY = "deny"
_HOLD = "hold"


class PdpUnavailable(Exception):
    """
    Raised by PdpClient.evaluate for ANY failure to obtain a valid verdict.

    Deliberately one type for transport faults, protocol faults, and malformed
    payloads alike: from the PEP's side they are the same event — "no usable
    answer from the PDP" — and they all take the same branch. Distinguishing
    them would invite a caller to treat one kind as benign.
    """


@dataclass(frozen=True)
class PepOutcome:
    """
    The harness-agnostic result of one enforcement check.

    A shim maps this into whatever its harness expects (Hermes wants
    ``{"action": "block", "message": ...}``; OpenClaw wants
    ``{block: true, blockReason}``). Keeping the mapping in the shim and the
    decision here is what lets one audited core serve every Python harness.
    """

    permit: bool
    reason: str = ""
    #: The wire decision string actually observed, or "" when none was obtained.
    #: Present for logging and tests; never re-derive `permit` from it.
    decision: str = ""
    #: Populated only when the PDP returns ALLOW with modified args. MODIFY is
    #: deferred past v1; this is the documented pass-through path.
    modified_args: Optional[dict] = None
    #: The raw wire elevation object on HOLD, so a shim can render a richer
    #: prompt than `reason` if its harness supports one.
    elevation: Optional[dict] = None
    #: The grant consumed to reach ALLOW, when the PDP reported one. Exists so a
    #: shim can log "proceeded under grant X" and correlate with the PDP audit
    #: trail WITHOUT reaching past this outcome for the raw verdict. That is the
    #: whole reason it is a named field: the seam does its job by being narrow.
    grant_id: Optional[str] = None


class _UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over AF_UNIX. Stdlib only — no third-party UDS transport."""

    def __init__(self, socket_path: str, timeout: float):
        # The host is a placeholder; nothing resolves it. The Host header it
        # produces is ignored by the PDP.
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # The same bound covers connect and every subsequent read, so a
        # responder that accepts and then stalls still trips the deadline.
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class PdpClient:
    """
    A fail-closed UDS client for the interlock PDP.

    Stateless and cheap to construct; one instance per plugin is fine. Not
    thread-safe for concurrent ``evaluate`` calls on the same instance — each
    call opens and closes its own connection, so concurrent callers should each
    hold their own client (or simply construct one per call).
    """

    def __init__(self, socket_path: str, timeout: float = DEFAULT_TIMEOUT,
                 max_response_bytes: int = MAX_RESPONSE_BYTES):
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes

    # -- public ------------------------------------------------------------

    def evaluate(self, call: ToolCall) -> dict:
        """
        Send one ToolCall and return the wire verdict dict.

        Raises PdpUnavailable on every failure path. Returns only a dict that
        carried a valid envelope with a string ``decision``; interpreting that
        string is `decide`'s job.
        """
        raw = self._post(self._encode(call))

        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise PdpUnavailable("unparseable response") from exc
        if not isinstance(msg, dict):
            raise PdpUnavailable("non-object response")
        # A version mismatch fails closed: never interpret an unknown format.
        if msg.get("schema_version") != SCHEMA_VERSION:
            raise PdpUnavailable("unrecognized schema_version")
        verdict = msg.get("verdict")
        if not isinstance(verdict, dict) or not isinstance(verdict.get("decision"), str):
            raise PdpUnavailable("invalid verdict envelope")
        return verdict

    # -- internals ---------------------------------------------------------

    def _encode(self, call: ToolCall) -> bytes:
        wire_call = toolcall_to_wire(call)
        # See module docstring, point 2: the PDP classifies, never the client.
        wire_call["effect"] = None
        return json.dumps(
            {"schema_version": SCHEMA_VERSION, "tool_call": wire_call}
        ).encode("utf-8")

    def _post(self, body: bytes) -> bytes:
        conn = _UnixHTTPConnection(self.socket_path, self.timeout)
        try:
            try:
                conn.request(
                    "POST",
                    _EVALUATE_PATH,
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(body)),
                    },
                )
                resp = conn.getresponse()
            except PdpUnavailable:
                raise
            except Exception as exc:
                # FileNotFoundError (no socket), ConnectionRefusedError (stale
                # socket file), socket.timeout, OSError, http.client errors —
                # every one of them is "no usable answer".
                raise PdpUnavailable(f"transport: {type(exc).__name__}") from exc

            if resp.status != 200:
                # The service answers a well-formed request with 200 + a DENY
                # verdict even for internal errors, so any other status means
                # something other than interlock is on this socket, or the
                # service is broken. Stricter than the JS client, and only ever
                # in the blocking direction.
                raise PdpUnavailable(f"unexpected status {resp.status}")

            try:
                # Read one byte past the cap so an oversized body is detectable
                # rather than silently truncated into something parseable.
                raw = resp.read(self.max_response_bytes + 1)
            except Exception as exc:
                # http.client.IncompleteRead lands here: a short body against a
                # declared Content-Length is a partial read, which blocks.
                raise PdpUnavailable(f"read failed: {type(exc).__name__}") from exc
            if len(raw) > self.max_response_bytes:
                raise PdpUnavailable("oversized response")
            return raw
        finally:
            try:
                conn.close()
            except Exception:
                pass


def hold_summary(verdict: dict) -> str:
    """Human-readable summary of a HOLD, mirroring the JS holdSummary()."""
    elevation = verdict.get("elevation")
    if not isinstance(elevation, dict):
        return "held: requires approval"
    try:
        scope = json.dumps(elevation.get("scope"))
    except Exception:
        scope = str(elevation.get("scope"))
    return (
        f"held: requires approval for {elevation.get('capability')} on {scope} "
        f"(call {elevation.get('call_id')}). An operator must approve "
        f"out-of-band; the agent then re-issues."
    )


def decide(client: PdpClient, call: ToolCall) -> PepOutcome:
    """
    Evaluate one ToolCall and return the enforcement outcome.

    NEVER RAISES. Any exception — transport, protocol, or an outright bug in
    this module — becomes a blocking PepOutcome. See the module docstring: in a
    harness that swallows hook exceptions, an escaping exception is an ALLOW.
    """
    try:
        try:
            verdict = client.evaluate(call)
        except PdpUnavailable:
            return PepOutcome(permit=False, reason=PDP_UNAVAILABLE_REASON)

        decision = verdict.get("decision")

        if decision == _ALLOW:
            modified = verdict.get("modified_args")
            grant_id = verdict.get("grant_id")
            return PepOutcome(
                permit=True,
                decision=_ALLOW,
                modified_args=modified if isinstance(modified, dict) else None,
                grant_id=grant_id if isinstance(grant_id, str) else None,
            )
        if decision == _DENY:
            reason = verdict.get("reason")
            return PepOutcome(
                permit=False,
                decision=_DENY,
                reason=reason if isinstance(reason, str) and reason else "denied",
            )
        if decision == _HOLD:
            elevation = verdict.get("elevation")
            return PepOutcome(
                permit=False,
                decision=_HOLD,
                reason=hold_summary(verdict),
                elevation=elevation if isinstance(elevation, dict) else None,
            )

        # "pass", "modify", or anything unrecognized: do not guess.
        return PepOutcome(permit=False, reason=PDP_UNAVAILABLE_REASON)
    except Exception:
        # Outermost net. Nothing gets past this, including a bug above.
        return PepOutcome(permit=False, reason=PDP_UNAVAILABLE_REASON)
