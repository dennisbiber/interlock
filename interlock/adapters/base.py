"""
interlock.adapters.base — the HarnessAdapter contract (plan §2).

An adapter is the bridge for one specific PEP: it normalizes a harness-specific
tool-call event into a ToolCall, translates a Verdict back into whatever that
harness expects, and registers the hook. The PDP never imports a harness; the
adapter never imports filter logic.

This Python Protocol is the contract for PYTHON-hosted PEPs (LangChain, CrewAI,
a custom loop). The OpenClaw PEP in ./openclaw/ is JavaScript and implements the
same three responsibilities in JS against the frozen wire schema — it does not
implement this Python Protocol, but it mirrors it, so the shapes stay parallel
across languages.

Fail-closed (invariant #5) is the adapter's responsibility on the enforcement
side: if the PDP is unreachable, times out, or returns anything that isn't an
explicit ALLOW, from_verdict/attach must BLOCK the tool, never permit it.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from interlock.types import ToolCall, Verdict


@runtime_checkable
class HarnessAdapter(Protocol):
    name: str

    def to_toolcall(self, raw: Any) -> ToolCall:
        """Normalize a harness-specific tool-call event into a ToolCall.

        Must set a STABLE session_id (one identity per agent run — this is what
        ties a runaway loop to one identity) and a unique call_id, and must leave
        effect as None so the PDP classifies it (invariant #4)."""
        ...

    def from_verdict(self, verdict: Verdict, raw: Any) -> Any:
        """Translate a Verdict into the harness's expected block/permit shape.

        Only an explicit ALLOW permits. DENY blocks terminally; HOLD blocks with
        the elevation surfaced for out-of-band approval and re-issue."""
        ...

    def attach(self, target: Any) -> None:
        """Register the enforcement hook at the harness's tool-execution boundary."""
        ...
