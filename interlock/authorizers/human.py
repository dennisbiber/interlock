"""
interlock.authorizers.human — the human-in-the-loop approver (§7).

HumanApprover emits the elevation request to a Channel and waits for a yes/no.
On yes it mints a SINGLE-USE, short-TTL, action-scoped grant matching exactly
the request's capability and scope, so the re-issued call consumes it and
nothing else. On no it returns None and the pipeline denies. It is the "bouncer
who can't be bought": there is no path to approval that doesn't go through the
channel.
"""

from __future__ import annotations

import sys
from typing import Optional

from interlock.types import ElevationRequest, Grant


class StdinChannel:
    """Default P2 channel: print the prompt, read one line, yes iff y/yes."""

    def __init__(self, in_stream=None, out_stream=None):
        self._in = in_stream if in_stream is not None else sys.stdin
        self._out = out_stream if out_stream is not None else sys.stdout

    def ask(self, prompt: str) -> bool:
        self._out.write(prompt + "\n[approve? y/N] ")
        self._out.flush()
        line = self._in.readline()
        return line.strip().lower() in ("y", "yes")


class HumanApprover:
    name = "HumanApprover"

    def __init__(self, ledger, channel, ttl: Optional[float] = 120.0):
        self._ledger = ledger      # mint-capable; only authorizers hold this
        self._channel = channel
        self._ttl = ttl

    def authorize(self, req: ElevationRequest) -> Optional[Grant]:
        if self._channel.ask(self._format(req)):
            return self._ledger.mint(
                capability=req.capability,
                scope=req.scope,
                uses=1,               # single-use in v1
                ttl=self._ttl,        # short-lived
                granted_by="human",
            )
        return None

    @staticmethod
    def _format(req: ElevationRequest) -> str:
        c = req.call
        return (
            f"Agent wants to run '{c.tool_name}' (effect: {req.capability})\n"
            f"  scope: {req.scope}\n"
            f"  args:  {c.args}\n"
            f"  session: {c.session_id}  call: {c.call_id}"
        )
