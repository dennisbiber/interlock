"""
interlock.authorizers.base — the elevation-handshake protocols (§7).

An Authorizer is the PAM-module analogue: it turns an ElevationRequest into a
Grant, or refuses. It is the ONLY component that holds a mint-capable ledger
reference (invariant #3) — the filter chain never does. Whether a grant is
minted, and with what lifetime/scope, is entirely the authorizer's call; the
pipeline just routes HOLDs to it and re-runs the chain if a grant comes back.

A Channel abstracts the human I/O for HumanApprover (stdin now; ntfy/webhook/
Slack later) so the approval transport can change without touching approval
logic, and so tests can feed a scripted answer instead of real stdin.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from interlock.types import ElevationRequest, Grant


@runtime_checkable
class Authorizer(Protocol):
    name: str

    def authorize(self, req: ElevationRequest) -> Optional[Grant]:
        """Return a freshly minted Grant to approve, or None to refuse."""
        ...


@runtime_checkable
class Channel(Protocol):
    def ask(self, prompt: str) -> bool:
        """Present the prompt to a human and return True for approve, False for deny."""
        ...
