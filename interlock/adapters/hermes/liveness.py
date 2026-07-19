"""
interlock.adapters.hermes.liveness — proof that the hook actually enforces.

THE FAILURE THIS EXISTS TO CATCH
--------------------------------
Harnesses have shipped builds where a pre-tool hook is registered successfully
and then never invoked in the execution path. Registration succeeding proves
nothing. An adapter that trusts registration is an adapter that looks installed
and enforces nothing, which is worse than no adapter at all, because it buys
false confidence.

So this module never asks "did registration succeed?". It asks three narrower
questions, each of which can fail independently:

  1. WIRING  — do the tool-dispatch modules in the INSTALLED Hermes actually
     call ``resolve_pre_tool_block``? Read their source and look. This is the
     direct test for silent-no-fire: a build where the hook runner exists but
     nothing calls it fails here, before any probe runs.

  2. ENFORCE — drive a canary tool through Hermes's own centralized directive
     resolver and require that OUR block message comes back. This proves the
     callback is registered, reachable, invoked, and that its block directive
     is honored — end to end, through Hermes's code rather than ours.

  3. FAULT   — drive a canary that makes our hook raise internally, and require
     a block anyway. Hermes swallows hook exceptions and then executes the tool,
     so an escaping exception is an ALLOW in this harness. This proves the
     exception-to-block conversion holds in the real hook path, in this install.

Every check runs against the installed Hermes, not against documentation.


THE HONEST LIMIT
----------------
Checks 2 and 3 drive ``hermes_cli.plugins.resolve_pre_tool_block``, which is the
single entry point all four tool-dispatch sites call. So they prove enforcement
along that function. Check 1 is what connects that function to the dispatch
sites, by reading the installed source. Together that is strong evidence, but it
is not the same as having a model issue a real tool call: a build that reached
tool execution by some fifth path this check does not know about would not be
caught. If you find such a path, it belongs in DISPATCH_MODULES below.
"""

from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass, field
from typing import List

from interlock.adapters.hermes.plugin import (
    CANARY_ENFORCE_TOKEN,
    CANARY_MODE_ENFORCE,
    CANARY_MODE_FAULT,
    CANARY_TOOL,
    import_hermes_plugins,
)

#: Modules in the installed Hermes that must call into the pre-tool gate for a
#: model-issued tool call to be enforced. Verified by reading hermes-agent
#: 0.18.2: model_tools.py:1179, agent/tool_executor.py:419 and :1038,
#: agent/agent_runtime_helpers.py:2123.
DISPATCH_MODULES = (
    "model_tools",
    "agent.tool_executor",
    "agent.agent_runtime_helpers",
)

#: The function every dispatch site funnels through.
GATE_SYMBOL = "resolve_pre_tool_block"


class LivenessError(RuntimeError):
    """Raised by assert_live() when enforcement cannot be proven."""


@dataclass
class LivenessReport:
    wiring_ok: bool = False
    enforce_ok: bool = False
    fault_ok: bool = False
    wired_modules: List[str] = field(default_factory=list)
    unwired_modules: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.wiring_ok and self.enforce_ok and self.fault_ok

    def summary(self) -> str:
        return (
            f"liveness: wiring={'ok' if self.wiring_ok else 'FAIL'} "
            f"enforce={'ok' if self.enforce_ok else 'FAIL'} "
            f"fault={'ok' if self.fault_ok else 'FAIL'} "
            f"({len(self.wired_modules)}/{len(DISPATCH_MODULES)} dispatch "
            f"modules call {GATE_SYMBOL})"
        )

    def details(self) -> str:
        lines = [self.summary()]
        if self.unwired_modules:
            lines.append(
                "  dispatch modules that do NOT call "
                f"{GATE_SYMBOL}: {', '.join(self.unwired_modules)}"
            )
            lines.append(
                "  -> this is the silent-no-fire shape: the hook can be "
                "registered and still never run."
            )
        for err in self.errors:
            lines.append(f"  {err}")
        return "\n".join(lines)


def check_wiring(report: LivenessReport) -> None:
    """Confirm the installed dispatch modules actually call the gate."""
    for name in DISPATCH_MODULES:
        try:
            # dynamic-import: iterates DISPATCH_MODULES, an in-repo tuple of
            # literals naming the OPTIONAL harness's own modules. Nothing in
            # the enforcement path requires any of them to import.
            module = importlib.import_module(name)
            source = inspect.getsource(module)
        except Exception as exc:
            report.unwired_modules.append(name)
            report.errors.append(f"could not read source of {name}: {exc!r}")
            continue
        if GATE_SYMBOL in source:
            report.wired_modules.append(name)
        else:
            report.unwired_modules.append(name)

    # Every known dispatch path must be wired. A partial result means some
    # execution paths are gated and others are not, which is not a posture
    # worth arming for — an agent would be guarded on one route and free on
    # another, with nothing in the logs to say which it took.
    report.wiring_ok = bool(report.wired_modules) and not report.unwired_modules


def check_enforce(report: LivenessReport, plugins_module=None) -> None:
    """Drive a canary through Hermes's own resolver; require our block back."""
    try:
        plugins = plugins_module or import_hermes_plugins()
        message = plugins.resolve_pre_tool_block(
            CANARY_TOOL,
            {"mode": CANARY_MODE_ENFORCE},
            session_id="interlock-liveness",
            tool_call_id="interlock-liveness-enforce",
        )
    except Exception as exc:
        report.errors.append(f"enforce probe raised: {exc!r}")
        return

    if message is None:
        report.errors.append(
            "enforce probe: the canary was NOT blocked. The hook is registered "
            "but its block directive did not take effect."
        )
        return
    if CANARY_ENFORCE_TOKEN not in message:
        # Something blocked the canary, but not us. Passing on that would be
        # exactly the false confidence this check exists to deny.
        report.errors.append(
            "enforce probe: the canary was blocked by something other than "
            f"interlock (message did not contain the token): {message!r}"
        )
        return
    report.enforce_ok = True


def check_fault(report: LivenessReport, plugins_module=None) -> None:
    """Make the hook raise internally; require a block anyway."""
    try:
        plugins = plugins_module or import_hermes_plugins()
        message = plugins.resolve_pre_tool_block(
            CANARY_TOOL,
            {"mode": CANARY_MODE_FAULT},
            session_id="interlock-liveness",
            tool_call_id="interlock-liveness-fault",
        )
    except Exception as exc:
        # The exception escaped the hook and reached us. In a real dispatch it
        # would instead be swallowed by invoke_hook and the tool would run.
        report.errors.append(
            f"fault probe: exception escaped the hook ({exc!r}). In this "
            "harness an escaping exception is an ALLOW."
        )
        return

    if message is None:
        report.errors.append(
            "fault probe: an internal hook error did NOT produce a block. "
            "A bug in the hook would silently permit tool calls."
        )
        return
    report.fault_ok = True


def run_liveness_check(plugins_module=None) -> LivenessReport:
    """Run all three checks and return a report. Never raises."""
    report = LivenessReport()
    try:
        check_wiring(report)
        check_enforce(report, plugins_module)
        check_fault(report, plugins_module)
    except Exception as exc:  # pragma: no cover - defensive
        report.errors.append(f"liveness check itself failed: {exc!r}")
    return report


def assert_live(plugins_module=None) -> LivenessReport:
    """Run the checks and raise LivenessError unless all three pass."""
    report = run_liveness_check(plugins_module)
    if not report.ok:
        raise LivenessError(report.details())
    return report
