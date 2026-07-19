"""
interlock.adapters.hermes.plugin — the Hermes PEP shim (H1).

THIN BY MANDATE. Every security-critical decision lives in
``interlock.adapters.pdp_client``. This module does four things and nothing
else: register the hook, extract context, call the shared core, and map the
outcome into Hermes's directive shape. When Hermes's API shifts, only this
moves.

The whole mapping is three lines in ``_directive``. That smallness is the
evidence the seam is right.


WHY THIS REGISTERS BEFORE IT VERIFIES
-------------------------------------
The handoff said an adapter that cannot prove enforcement must "fail loud —
refuse to run". In Hermes, raising from ``register()`` does the OPPOSITE of
that. ``PluginManager._load_plugin`` wraps the ``register(ctx)`` call in a bare
``except Exception`` and only logs a warning:

    except Exception as exc:
        loaded.error = str(exc)
        logger.warning("Failed to load plugin '%s': %s", ...)

So a plugin that raises to protest is a plugin whose hook was never registered,
in an agent that starts anyway and runs completely ungated. It looks installed
and enforces nothing — the exact failure this project exists to prevent.

The inversion: register the hook FIRST in a **fail-closed posture that denies
every tool call**, and only arm normal enforcement once liveness has proven the
hook actually enforces. Then every failure mode is safe:

  * liveness fails            -> hook is registered and denying; agent is inert
  * register() dies midway    -> hook already registered and denying
  * Hermes swallows our error  -> irrelevant; the denial is already in place

An operator meets an agent that refuses to act, which is unmissable and safe,
rather than one that acts freely while appearing guarded.


WHY THE CALLBACK MUST NEVER RAISE
---------------------------------
``PluginManager.invoke_hook`` wraps each callback in try/except and logs a
warning on exception. A raising callback contributes no directive, so
``resolve_pre_tool_block`` returns None and the tool EXECUTES. In this harness
an escaping exception is an ALLOW. ``on_pre_tool_call`` therefore catches
``Exception`` at its outermost level and converts it into a block.


WHY THE SIGNATURE ENDS IN **kwargs
----------------------------------
``invoke_hook`` injects ``telemetry_schema_version`` into every hook call on top
of the documented kwargs, and may add more later. A callback whose signature
does not absorb unexpected keywords raises TypeError, which is swallowed, which
is an allow. The ``**kwargs`` is a fail-closed requirement, not tidiness.


WHY A BLOCK MESSAGE IS NEVER EMPTY
----------------------------------
``_get_pre_tool_call_directive_details`` skips a block directive that carries no
message:

    if action == "block" and not message:
        continue

An empty message is therefore an ALLOW. Every block this module emits is
guaranteed a non-empty message by ``_directive``.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
import uuid
from typing import Any, Optional

from interlock.adapters.pdp_client import (
    DEFAULT_TIMEOUT,
    PdpClient,
    PepOutcome,
    decide,
)
from interlock.types import ToolCall

logger = logging.getLogger("interlock.adapters.hermes")

# Imported dynamically, by string, so the shipped `interlock/` package keeps a
# stdlib-only static import surface (scripts/check_no_runtime_deps.py walks the
# AST and does not care whether an import is lazy). This is a declared optional
# harness module, not an evasion — the gate enforces that allowlist directly.
HERMES_PLUGINS_MODULE = "hermes_cli.plugins"

#: Versions this adapter has been verified against by reading their source.
#: An unexpected version WARNS and proceeds — version strings lie, and pinning
#: creates false confidence. The liveness check is the real gate: behavior is
#: the contract.
VERIFIED_HERMES_VERSIONS = ("0.18.2",)

#: The canary tool name. Never a real tool; short-circuited inside this module
#: so a liveness probe never reaches the PDP or the network.
CANARY_TOOL = "__interlock_liveness_canary__"
CANARY_MODE_ENFORCE = "enforce"
CANARY_MODE_FAULT = "fault"

#: Tokens the liveness check matches on. Distinct strings so a probe cannot pass
#: by accident — e.g. because some other plugin also blocked the canary.
CANARY_ENFORCE_TOKEN = "interlock-liveness-canary-enforced-4f2b91"
CANARY_FAULT_TOKEN = "interlock-liveness-canary-fault-caught-8ac3e7"

#: Emitted when the plugin is registered but liveness has not (yet) passed.
UNVERIFIED_MESSAGE = (
    "BLOCKED by interlock: enforcement could not be verified in this Hermes "
    "install, so every tool call is denied. This is the fail-closed posture, "
    "not a bug. Check the interlock liveness report in the agent log."
)

#: Emitted when anything inside this module goes wrong. Never empty.
INTERNAL_ERROR_MESSAGE = (
    "BLOCKED by interlock: the enforcement hook hit an internal error and "
    "failed closed."
)

ENV_SOCKET = "INTERLOCK_SOCKET"
ENV_TIMEOUT = "INTERLOCK_TIMEOUT"
ENV_EXIT_ON_LIVENESS_FAILURE = "INTERLOCK_EXIT_ON_LIVENESS_FAILURE"


def import_hermes_plugins():
    """Import Hermes's plugin module. Raises ImportError when Hermes is absent."""
    return importlib.import_module(HERMES_PLUGINS_MODULE)


def hermes_version() -> Optional[str]:
    """Installed hermes-agent version, or None when it cannot be determined."""
    try:
        from importlib.metadata import version

        return version("hermes-agent")
    except Exception:
        return None


class InterlockHermesPlugin:
    """
    The PEP shim. One instance per agent process.

    Starts UNARMED: every tool call is denied until :meth:`arm` is called, which
    the liveness check does only after proving the hook enforces.
    """

    name = "hermes"

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout: Optional[float] = None,
        session_id: Optional[str] = None,
        client: Optional[PdpClient] = None,
    ):
        self.socket_path = socket_path or os.environ.get(ENV_SOCKET, "")
        try:
            self.timeout = float(timeout if timeout is not None
                                 else os.environ.get(ENV_TIMEOUT, DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout = DEFAULT_TIMEOUT

        self._client = client or PdpClient(self.socket_path, timeout=self.timeout)

        # One identity per agent process. Hermes supplies a session_id per call
        # and we prefer it, but an unattended run that never sets one still
        # needs a STABLE identity — that is what ties a runaway loop to a single
        # subject in the ledger and the audit log. A per-call UUID would make
        # every call look like a fresh agent.
        self._fallback_session_id = session_id or f"hermes-{uuid.uuid4()}"

        self._armed = False

    # -- posture -----------------------------------------------------------

    @property
    def armed(self) -> bool:
        return self._armed

    def arm(self) -> None:
        """Enable normal enforcement. Only the liveness check should call this."""
        self._armed = True

    def disarm(self) -> None:
        """Return to deny-everything. Not reversible except through arm()."""
        self._armed = False

    # -- the hook ----------------------------------------------------------

    def on_pre_tool_call(
        self,
        tool_name: Any = None,
        args: Any = None,
        session_id: Any = "",
        tool_call_id: Any = "",
        turn_id: Any = "",
        task_id: Any = "",
        api_request_id: Any = "",
        **kwargs: Any,
    ) -> Optional[dict]:
        """
        Hermes ``pre_tool_call`` callback.

        Returns None to permit, or ``{"action": "block", "message": ...}`` to
        block. NEVER RAISES — see the module docstring.
        """
        try:
            return self._evaluate(
                tool_name=tool_name,
                args=args,
                session_id=session_id,
                tool_call_id=tool_call_id,
                turn_id=turn_id,
                task_id=task_id,
                api_request_id=api_request_id,
            )
        except Exception:
            logger.exception("interlock hook failed internally; blocking")
            return self._directive(INTERNAL_ERROR_MESSAGE)

    # -- internals ---------------------------------------------------------

    def _evaluate(self, *, tool_name, args, session_id, tool_call_id,
                  turn_id, task_id, api_request_id) -> Optional[dict]:
        if tool_name == CANARY_TOOL:
            return self._canary(args)

        if not self._armed:
            return self._directive(UNVERIFIED_MESSAGE)

        call = self.to_toolcall(
            tool_name=tool_name,
            args=args,
            session_id=session_id,
            tool_call_id=tool_call_id,
            turn_id=turn_id,
            task_id=task_id,
            api_request_id=api_request_id,
        )
        return self.from_outcome(decide(self._client, call))

    def _canary(self, args: Any) -> Optional[dict]:
        """
        Short-circuit the liveness probes. Never touches the PDP.

        The fault probe raises deliberately so the outer handler in
        ``on_pre_tool_call`` has to catch it — that is the point: it proves the
        exception-to-block conversion works in this install, in the real hook
        path, rather than only in a unit test.
        """
        mode = args.get("mode") if isinstance(args, dict) else None
        if mode == CANARY_MODE_FAULT:
            raise RuntimeError(f"induced liveness fault ({CANARY_FAULT_TOKEN})")
        return self._directive(CANARY_ENFORCE_TOKEN)

    def to_toolcall(self, *, tool_name, args, session_id, tool_call_id,
                    turn_id="", task_id="", api_request_id="") -> ToolCall:
        """
        Normalize a Hermes hook invocation into a ToolCall.

        ``effect`` stays None: the PDP classifies (invariant #4). The shared
        client blanks it again on the wire regardless.
        """
        return ToolCall(
            tool_name=tool_name if isinstance(tool_name, str) else str(tool_name),
            args=args if isinstance(args, dict) else {},
            # Hermes's own session id when it supplies one — it correlates the
            # interlock audit log with Hermes's session records.
            session_id=session_id if isinstance(session_id, str) and session_id
            else self._fallback_session_id,
            # Hermes's own tool_call_id when present, for the same reason.
            call_id=tool_call_id if isinstance(tool_call_id, str) and tool_call_id
            else str(uuid.uuid4()),
            effect=None,
            meta={
                "harness": "hermes",
                "turn_id": turn_id if isinstance(turn_id, str) else "",
                "task_id": task_id if isinstance(task_id, str) else "",
                "api_request_id": api_request_id if isinstance(api_request_id, str) else "",
            },
        )

    def from_outcome(self, outcome: PepOutcome) -> Optional[dict]:
        """Map a PepOutcome onto Hermes's directive shape. The entire mapping."""
        if outcome.permit:
            if outcome.grant_id:
                logger.info("interlock: proceeding under grant %s", outcome.grant_id)
            return None
        return self._directive(outcome.reason)

    @staticmethod
    def _directive(message: str) -> dict:
        # A block directive with a falsy message is DISCARDED by Hermes and the
        # tool runs. Guaranteeing non-empty here is a fail-closed requirement.
        text = message if isinstance(message, str) and message.strip() else INTERNAL_ERROR_MESSAGE
        return {"action": "block", "message": text}

    # -- registration ------------------------------------------------------

    def attach(self, ctx: Any) -> None:
        """Register the hook. Deliberately the FIRST thing register() does."""
        ctx.register_hook("pre_tool_call", self.on_pre_tool_call)


def register(ctx: Any) -> None:
    """
    Hermes plugin entry point.

    Order matters and is the whole safety argument — see the module docstring.
    The hook goes in denying; liveness arms it or it stays denying.
    """
    plugin = InterlockHermesPlugin()

    # 1. Register FIRST, unarmed. From here on, a failure anywhere below leaves
    #    an agent that blocks every tool call rather than one that runs free.
    plugin.attach(ctx)

    installed = hermes_version()
    if installed is not None and installed not in VERIFIED_HERMES_VERSIONS:
        logger.warning(
            "interlock: hermes-agent %s has not been source-verified by this "
            "adapter (verified: %s). Proceeding — the liveness check, not the "
            "version string, is the gate.",
            installed, ", ".join(VERIFIED_HERMES_VERSIONS),
        )

    if not plugin.socket_path:
        _fail_loud(
            "interlock: no PDP socket configured. Set INTERLOCK_SOCKET to the "
            "PDP's unix socket path. Every tool call is being DENIED."
        )
        return

    # 2. Prove the hook enforces before trusting it to.
    from interlock.adapters.hermes.liveness import run_liveness_check

    report = run_liveness_check()
    if report.ok:
        plugin.arm()
        logger.warning(
            "interlock: enforcement ARMED for Hermes (socket=%s). %s",
            plugin.socket_path, report.summary(),
        )
        return

    _fail_loud(
        "interlock: LIVENESS CHECK FAILED — enforcement could not be proven in "
        "this Hermes install. Every tool call is being DENIED.\n" + report.details()
    )


def _fail_loud(message: str) -> None:
    """
    Make an enforcement failure impossible to miss.

    Hermes logs plugin problems at warning level into a file most operators
    never read, so this also goes to stderr. Setting
    INTERLOCK_EXIT_ON_LIVENESS_FAILURE=1 turns it into a hard stop for
    unattended deployments, where a blocked-everything agent burning tokens in a
    loop is worse than no agent.
    """
    logger.error("%s", message)
    print(f"\n{'=' * 78}\n{message}\n{'=' * 78}\n", file=sys.stderr, flush=True)
    if os.environ.get(ENV_EXIT_ON_LIVENESS_FAILURE, "").strip() in ("1", "true", "yes"):
        os._exit(70)  # EX_SOFTWARE; _exit because we are inside a swallowed call
