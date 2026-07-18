"""
Vendored persistence primitives, copied verbatim from LMContextCompiler with
public APIs unchanged. Only session_store.py's internal import path was
retargeted to this package; StateStore is byte-identical to the source.
"""

from interlock.store.state_store import StateStore
from interlock.store.session_store import SessionStore

__all__ = ["StateStore", "SessionStore"]
