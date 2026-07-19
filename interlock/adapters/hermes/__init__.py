"""interlock Hermes PEP adapter. See plugin.py for the safety argument."""

from interlock.adapters.hermes.plugin import (  # noqa: F401
    CANARY_TOOL,
    InterlockHermesPlugin,
    register,
)

__all__ = ["InterlockHermesPlugin", "register", "CANARY_TOOL"]
