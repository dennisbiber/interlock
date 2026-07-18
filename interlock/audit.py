"""
interlock.audit — the audit sink (§10).

Audit is a CROSS-CUTTING SINK, not a filter: the pipeline calls it once per
evaluate() with the FINAL verdict; it never sits in the filter chain and never
influences a verdict.

Persistence is append-only JSON Lines (one JSON object per line), deliberately
NOT SessionStore. Audit is the canonical append workload; SessionStore's
whole-snapshot model would rewrite the entire history on every record (O(n) per
write, O(n**2) cumulative, unbounded in-memory). JSONL is O(1) append, constant
memory, and append-only is more tamper-evident than a full-file rewrite. The
grant ledger stays on SessionStore; only audit deviates.

Records are plain dicts (never dataclasses — same _json_safe reason as grants).

Robustness (v1 audit is observational): a write failure is logged loudly but
must NEVER raise into evaluate() and NEVER change a verdict. A failed audit must
not turn a DENY into an ALLOW. The pipeline additionally wraps the sink call, so
even a misbehaving custom sink cannot break enforcement.

Follow-up (not in P3): size/time-based rotation and retention. JSONL makes this
trivial to add later (rotate the file, keep N segments) — a reason to pick it now.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Protocol, runtime_checkable

logger = logging.getLogger("interlock.audit")


@runtime_checkable
class AuditSink(Protocol):
    def record(self, entry: dict) -> None:
        """Persist one audit record. Must not raise; failures are swallowed + logged."""
        ...


class JsonlAuditLog:
    """Append-only JSON Lines audit sink."""

    def __init__(self, path: str):
        self._path = path

    def record(self, entry: dict) -> None:
        try:
            parent = os.path.dirname(os.path.abspath(self._path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            line = json.dumps(entry, default=str)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
        except Exception:
            # Never propagate: audit is observational, enforcement must proceed.
            logger.exception("audit append failed for %s", self._path)

    def read_all(self) -> list:
        """Read every record back (for tests / introspection)."""
        records = []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except FileNotFoundError:
            pass
        return records
