"""
A faithful mock of Hermes's plugin surface, for CI.

Mirrors ``mock_openclaw.js``: tests must run with no GPU, no model, no network
and no real Hermes install. Every behavior reproduced here was read out of
hermes-agent 0.18.2's installed source, and the ones that matter are the
UNFRIENDLY ones — a forgiving mock would let the adapter pass while the real
harness silently allowed everything.

Reproduced deliberately, with the source location each came from:

  * ``invoke_hook`` injects ``telemetry_schema_version`` into every call on top
    of the documented kwargs (plugins.py:1910). A callback that cannot absorb
    an unexpected keyword raises TypeError.
  * ``invoke_hook`` wraps each callback in try/except and only logs
    (plugins.py:1913-1924). A raising callback contributes NO directive, so the
    tool proceeds. In this harness an escaping exception is an allow.
  * a ``block`` directive with a falsy message is DISCARDED
    (plugins.py:~2160). An empty message is an allow.
  * only dicts whose ``action`` is ``block`` or ``approve`` count; the first
    valid directive wins and the rest are ignored.
  * ``_load_plugin`` wraps ``register(ctx)`` in except Exception and only logs a
    warning (plugins.py:1822). A plugin that raises to protest is a plugin that
    never registered, in an agent that starts anyway.
  * ``PluginContext.register_hook`` WARNS on an unknown hook name and stores it
    anyway, for forward compatibility. A typo'd hook name therefore registers
    successfully and fires never.
"""

from __future__ import annotations

OBSERVER_SCHEMA_VERSION = 3

VALID_HOOKS = {
    "pre_tool_call",
    "post_tool_call",
    "pre_llm_call",
    "post_llm_call",
    "on_session_start",
    "on_session_end",
}


class MockPluginContext:
    """Stands in for the ctx object Hermes hands to register()."""

    def __init__(self, manager):
        self._manager = manager

    def register_hook(self, hook_name, callback):
        # The real PluginContext.register_hook WARNS on an unknown hook name and
        # STORES IT ANYWAY, "so forward-compatible plugins don't break". So a
        # typo'd hook name registers successfully, fires never, and reports no
        # error — silent-no-fire produced by a one-character mistake.
        #
        # A mock that raised here would be stricter than reality and would let
        # the adapter pass tests it would fail in production. It is the liveness
        # check's enforce probe that must catch this, not the mock.
        if hook_name not in VALID_HOOKS:
            self._manager.warnings.append(f"unknown hook {hook_name!r}")
        self._manager.hooks.setdefault(hook_name, []).append(callback)


class MockHermes:
    """
    A stand-in PluginManager exposing the module-level API the adapter uses.

    Instantiate, then either call methods directly or use `install()` to put it
    in sys.modules as `hermes_cli.plugins`.
    """

    def __init__(self):
        self.hooks = {}
        self.warnings = []       # unknown hook names, stored anyway
        self.swallowed = []       # exceptions invoke_hook ate, as the real one does
        self.approval_responses = []

    # -- registration ------------------------------------------------------

    def context(self):
        return MockPluginContext(self)

    def load_plugin(self, register_fn):
        """
        Mirror _load_plugin: call register(ctx), swallow any exception.

        Returns the exception it swallowed, or None. The agent starts either
        way — which is the point.
        """
        ctx = self.context()
        try:
            register_fn(ctx)
            return None
        except Exception as exc:
            self.swallowed.append(exc)
            return exc

    def has_hook(self, hook_name):
        return bool(self.hooks.get(hook_name))

    # -- invocation --------------------------------------------------------

    def invoke_hook(self, hook_name, **kwargs):
        kwargs.setdefault("telemetry_schema_version", OBSERVER_SCHEMA_VERSION)
        results = []
        for cb in self.hooks.get(hook_name, []):
            try:
                ret = cb(**kwargs)
            except Exception as exc:
                # The real manager logs a warning and moves on. No directive is
                # produced, so the tool executes.
                self.swallowed.append(exc)
                continue
            if ret is not None:
                results.append(ret)
        return results

    def _directive_details(self, tool_name, args, **kwargs):
        for result in self.invoke_hook(
            "pre_tool_call", tool_name=tool_name, args=args if isinstance(args, dict) else {},
            **kwargs
        ):
            if not isinstance(result, dict):
                continue
            action = result.get("action")
            if action not in ("block", "approve"):
                continue
            message = result.get("message")
            message = message if isinstance(message, str) and message else None
            if action == "block" and not message:
                # A block with no message is discarded and the tool runs.
                continue
            return action, message
        return None, None

    def resolve_pre_tool_block(self, tool_name, args, task_id="", session_id="",
                               tool_call_id="", turn_id="", api_request_id="",
                               middleware_trace=None):
        """Return the block message, or None when the call may proceed."""
        action, message = self._directive_details(
            tool_name, args, task_id=task_id, session_id=session_id,
            tool_call_id=tool_call_id, turn_id=turn_id,
            api_request_id=api_request_id,
        )
        if action == "block":
            return message
        if action == "approve":
            approved = self.approval_responses.pop(0) if self.approval_responses else False
            if not approved:
                return message or f"BLOCKED: approval denied for {tool_name}"
            return None
        return None

    # -- sys.modules plumbing ---------------------------------------------

    def install(self, monkeypatch_modules):
        """
        Register self as `hermes_cli.plugins` in the given sys.modules-like dict.

        Returns a callable that restores the previous state.
        """
        import types

        pkg_existing = monkeypatch_modules.get("hermes_cli")
        mod_existing = monkeypatch_modules.get("hermes_cli.plugins")

        pkg = types.ModuleType("hermes_cli")
        pkg.__path__ = []
        mod = types.ModuleType("hermes_cli.plugins")
        mod.resolve_pre_tool_block = self.resolve_pre_tool_block
        mod.invoke_hook = self.invoke_hook
        mod.has_hook = self.has_hook
        mod.VALID_HOOKS = VALID_HOOKS
        pkg.plugins = mod
        monkeypatch_modules["hermes_cli"] = pkg
        monkeypatch_modules["hermes_cli.plugins"] = mod

        def restore():
            for key, previous in (("hermes_cli", pkg_existing),
                                  ("hermes_cli.plugins", mod_existing)):
                if previous is None:
                    monkeypatch_modules.pop(key, None)
                else:
                    monkeypatch_modules[key] = previous

        return restore
