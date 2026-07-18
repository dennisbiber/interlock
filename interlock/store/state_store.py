"""
StateStore — dictionary-backed dynamic state container.

Intentionally kept simple: no proxy magic, no attribute interception.
All access is explicit via .get() / .set() / .ensure().
A vector store backend can be swapped in later by subclassing and
overriding get/set/ensure.
"""

from typing import Any, Optional


class StateStore:
    """
    Key/value store for pipeline state.

    Usage:
        store = StateStore()
        store.set("scene_summary", "A rainy evening...")
        store.get("scene_summary")   # → "A rainy evening..."
        store.ensure("scene_summary")  # no-op if key already exists
    """

    def __init__(self):
        self._data: dict = {}

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    def ensure(self, key: str, default: Any = None) -> None:
        """Set key to default only if it doesn't exist yet."""
        if key not in self._data:
            self._data[key] = default

    def keys(self):
        return self._data.keys()

    def snapshot(self) -> dict:
        """Return a shallow copy of all state (for persistence)."""
        return dict(self._data)

    def restore(self, data: dict) -> None:
        """Restore state from a previously snapshotted dict."""
        self._data.update(data)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        return f"StateStore({self._data!r})"
