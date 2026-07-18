"""
interlock.filters.base — the Filter abstraction and the read-only views a
filter is allowed to see.

A filter is a pure opinion function: given a ToolCall and a FilterContext it
returns a FilterResult. Filters are handed a consume-only view of the ledger
(defense-in-depth — see ledger.ConsumeOnlyView for its honest limits) and a
read-only policy view. Module boundaries are Protocols, so no concrete
implementation (pipeline.Policy, ledger.ConsumeOnlyView) is imported here; the
concretes satisfy these structurally.

A filter may declare `consumes = True` if evaluating it spends a grant (as
GateKeeper does). The pipeline uses that marker to enforce, at construction,
that consuming filters run last — so a grant is never spent on a call a later
filter would deny or hold.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from interlock.types import ToolCall, FilterResult, Grant


@runtime_checkable
class ConsumeOnly(Protocol):
    """The only ledger capability a filter may hold: spend a grant, never mint one."""

    def find_and_consume(self, capability: str, scope: dict) -> Optional[Grant]: ...


@runtime_checkable
class PolicyView(Protocol):
    """Read-only policy surface a filter may consult."""

    def classify(self, tool_name: str) -> tuple[str, bool]:
        """Return (resolved_effect, is_passive) for a tool name."""
        ...

    def project_scope(self, tool_name: str, args: dict) -> dict:
        """Project the policy-declared stable identifying args into a scope dict."""
        ...

    def elevation_for(self, effect: str) -> Optional[str]:
        """Return the configured authorizer name for an effect, or None."""
        ...


@dataclass(frozen=True)
class FilterContext:
    """Shared, read-only services handed to every filter for one evaluation."""

    ledger: ConsumeOnly
    policy: PolicyView


@runtime_checkable
class Filter(Protocol):
    name: str
    # True if evaluating this filter spends a grant. Defaults to False for
    # filters that omit it (read via getattr); consuming filters must run last.
    consumes: bool

    def evaluate(self, call: ToolCall, ctx: FilterContext) -> FilterResult: ...
