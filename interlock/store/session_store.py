import json
import os
import logging
from pathlib import Path
from typing import Optional

from interlock.store.state_store import StateStore

logger = logging.getLogger(__name__)


class SessionStore:
    """
    Manages per-conversation state persistence.

    Each chat_id gets its own JSON file:
        <session_dir>/<chat_id>.json

    Usage:
        sessions = SessionStore("/app/state_sessions")
        store = sessions.load("abc-123")      # load or create fresh
        store.set("scene_summary", "...")
        sessions.save("abc-123", store)       # persist after pipeline run
    """

    def __init__(self, session_dir: Optional[str] = None):
        self.session_dir = Path(
            session_dir
            or os.environ.get("OWUI_STATE_SESSION_DIR", "/app/state_sessions")
        )
        self.session_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, chat_id: str) -> StateStore:
        """Load state for a conversation, or return a fresh StateStore."""
        path = self._path(chat_id)
        store = StateStore()
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                store.restore(data)
                logger.debug("Loaded session state for chat_id=%s", chat_id)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "Could not load session for %s (%s) — starting fresh.", chat_id, exc
                )
        return store

    def save(self, chat_id: str, store: StateStore) -> None:
        """Persist the current StateStore snapshot to disk."""
        path = self._path(chat_id)
        try:
            with path.open("w", encoding="utf-8") as f:
                json.dump(store.snapshot(), f, ensure_ascii=False, indent=2,
                          default=_json_safe)
            logger.debug("Saved session state for chat_id=%s", chat_id)
        except OSError as exc:
            logger.error("Could not save session for %s: %s", chat_id, exc)

    def delete(self, chat_id: str) -> None:
        """Delete a session (e.g. on conversation reset)."""
        path = self._path(chat_id)
        if path.exists():
            path.unlink()
            logger.debug("Deleted session state for chat_id=%s", chat_id)

    def exists(self, chat_id: str) -> bool:
        return self._path(chat_id).exists()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _path(self, chat_id: str) -> Path:
        return self.session_dir / f"{sanitize_id(chat_id)}.json"

def sanitize_id(raw_id: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in raw_id)


def _json_safe(obj):
    """Fallback serialiser — converts non-JSON-native types to strings."""
    try:
        return str(obj)
    except Exception:
        return None
