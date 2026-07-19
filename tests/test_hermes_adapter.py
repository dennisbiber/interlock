"""
Hermes adapter tests (H1.5).

Runs with no GPU, no model, no network and no real Hermes install: the harness
surface is mocked in tests/mock_hermes.py against behavior read out of
hermes-agent 0.18.2's installed source.

Covers conformance cases 10 and 11 — liveness passes when the hook enforces, and
FAILS LOUD when the hook is registered but never fires — which the shared
client's battery could not, because they are adapter-specific. Cases 1-9 and 12
are exercised here again through the plugin, since what matters for an adapter
is that the outcome reaches the harness in the right shape.
"""

import contextlib
import io
import logging
import os
import sys
import tempfile
import textwrap
import threading
import unittest
import uuid

from interlock import service
from interlock.adapters.hermes import liveness as liveness_mod
from interlock.adapters.hermes.plugin import (
    CANARY_ENFORCE_TOKEN,
    CANARY_MODE_FAULT,
    CANARY_TOOL,
    INTERNAL_ERROR_MESSAGE,
    UNVERIFIED_MESSAGE,
    InterlockHermesPlugin,
    register,
)
from interlock.adapters.pdp_client import PdpClient, PepOutcome
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore
from interlock.types import PDP_UNAVAILABLE_REASON
from tests.mock_hermes import MockHermes

# The plugin logs a full traceback whenever it converts an internal fault into
# a block — deliberate in production, pure noise here, and several tests induce
# that fault on purpose. Silenced for this module only.
logging.getLogger("interlock.adapters.hermes").setLevel(logging.CRITICAL)

POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_file": "fs:delete", "list_files": "read"},
    "tool_scopes": {"delete_file": ["path"]},
    "elevation": {"default": "HumanApprover"},
    "rate_limits": {"key": "session_effect", "default": None, "per_effect": {}},
}


def armed_plugin(**kw):
    p = InterlockHermesPlugin(**kw)
    p.arm()
    return p


# ---------------------------------------------------------------------------
# The three harness behaviors that turn an adapter bug into a silent allow.
# ---------------------------------------------------------------------------

class TestHarnessHostility(unittest.TestCase):
    """
    Each test here corresponds to a real Hermes behavior that converts an
    adapter mistake into an EXECUTED tool call. These are the tests most worth
    keeping if the file ever has to shrink.
    """

    def setUp(self):
        self.hermes = MockHermes()
        self.plugin = armed_plugin(socket_path="/nonexistent/interlock.sock")
        self.plugin.attach(self.hermes.context())

    def test_callback_absorbs_the_undocumented_telemetry_kwarg(self):
        # invoke_hook injects telemetry_schema_version on top of the documented
        # kwargs. A signature that cannot absorb it raises TypeError, which is
        # swallowed, which permits the tool.
        message = self.hermes.resolve_pre_tool_block("delete_file", {"path": "/a"})
        self.assertIsNotNone(message, "hook produced no directive; tool would run")
        self.assertEqual(self.hermes.swallowed, [], "hook raised and was swallowed")

    def test_hook_never_raises_even_on_an_internal_fault(self):
        # An exception escaping the callback is eaten by invoke_hook and the
        # tool executes. The canary's fault mode induces exactly that.
        message = self.hermes.resolve_pre_tool_block(
            CANARY_TOOL, {"mode": CANARY_MODE_FAULT})
        self.assertEqual(message, INTERNAL_ERROR_MESSAGE)
        self.assertEqual(self.hermes.swallowed, [],
                         "an exception reached invoke_hook; in Hermes that is an allow")

    def test_block_message_is_never_empty(self):
        # Hermes discards a block directive with a falsy message and runs the
        # tool. Every path through the plugin must produce a non-empty message.
        for reason in ("", "   ", None, 0, [], {}):
            with self.subTest(reason=reason):
                directive = self.plugin.from_outcome(
                    PepOutcome(permit=False, reason=reason))
                self.assertEqual(directive["action"], "block")
                self.assertTrue(
                    directive["message"] and directive["message"].strip(),
                    "an empty block message is discarded by Hermes = allow")

    def test_a_hook_that_returns_none_would_permit(self):
        # Documents the harness contract this adapter is fighting: nothing
        # registered means nothing blocked.
        empty = MockHermes()
        self.assertIsNone(empty.resolve_pre_tool_block("delete_file", {"path": "/a"}))


# ---------------------------------------------------------------------------
# Registration order — the safety argument in plugin.register().
# ---------------------------------------------------------------------------

class TestRegistrationPosture(unittest.TestCase):

    def setUp(self):
        self.hermes = MockHermes()
        self.restore = self.hermes.install(sys.modules)
        self.addCleanup(self.restore)
        self._env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self._env)))
        os.environ.pop("INTERLOCK_EXIT_ON_LIVENESS_FAILURE", None)

    def test_hook_is_registered_even_when_no_socket_is_configured(self):
        os.environ.pop("INTERLOCK_SOCKET", None)
        with self._captured_stderr() as err:
            swallowed = self.hermes.load_plugin(register)
        self.assertIsNone(swallowed, "register() must not raise")
        self.assertTrue(self.hermes.has_hook("pre_tool_call"),
                        "no hook registered: the agent would run completely ungated")
        # Hermes logs plugin problems at warning level into a file most
        # operators never read, so the failure must also reach stderr.
        self.assertIn("DENIED", err.getvalue())

    @contextlib.contextmanager
    def _captured_stderr(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            yield buf

    def test_misconfigured_plugin_denies_every_tool_call(self):
        os.environ.pop("INTERLOCK_SOCKET", None)
        with self._captured_stderr():
            self.hermes.load_plugin(register)
        message = self.hermes.resolve_pre_tool_block("delete_file", {"path": "/etc/passwd"})
        self.assertEqual(message, UNVERIFIED_MESSAGE)

    def test_registration_survives_a_liveness_failure_and_stays_denying(self):
        os.environ["INTERLOCK_SOCKET"] = "/nonexistent/interlock.sock"
        # Simulate a Hermes build whose dispatch path never calls the gate. The
        # module must genuinely not contain the symbol — pointing this at a file
        # that merely mentions the name would make the check pass and prove
        # nothing.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        name = f"unwired_{uuid.uuid4().hex}"
        with open(os.path.join(tmp.name, f"{name}.py"), "w") as fh:
            fh.write("def dispatch(tool, args):\n    return None\n")
        sys.path.insert(0, tmp.name)
        self.addCleanup(lambda: sys.path.remove(tmp.name))
        sys.modules.pop(name, None)

        original = liveness_mod.DISPATCH_MODULES
        liveness_mod.DISPATCH_MODULES = (name,)
        self.addCleanup(lambda: setattr(liveness_mod, "DISPATCH_MODULES", original))

        with self._captured_stderr() as err:
            swallowed = self.hermes.load_plugin(register)
        self.assertIsNone(swallowed)
        self.assertTrue(self.hermes.has_hook("pre_tool_call"))
        self.assertEqual(
            self.hermes.resolve_pre_tool_block("delete_file", {"path": "/a"}),
            UNVERIFIED_MESSAGE)
        self.assertIn("LIVENESS CHECK FAILED", err.getvalue())
        self.assertIn("silent-no-fire", err.getvalue())


# ---------------------------------------------------------------------------
# Liveness: conformance cases 10 and 11.
# ---------------------------------------------------------------------------

class TestLiveness(unittest.TestCase):

    def setUp(self):
        self.hermes = MockHermes()
        self.plugin = InterlockHermesPlugin(socket_path="/nonexistent.sock")
        self.plugin.attach(self.hermes.context())

        # A temp package standing in for the installed Hermes dispatch modules,
        # so the wiring check has real source to read.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        sys.path.insert(0, self._tmp.name)
        self.addCleanup(lambda: sys.path.remove(self._tmp.name))

        self._original_modules = liveness_mod.DISPATCH_MODULES
        self.addCleanup(
            lambda: setattr(liveness_mod, "DISPATCH_MODULES", self._original_modules))

    def _write_module(self, name, calls_gate: bool):
        body = (
            "from hermes_cli.plugins import resolve_pre_tool_block\n"
            "def dispatch(tool, args):\n"
            "    blocked = resolve_pre_tool_block(tool, args)\n"
            "    return blocked\n"
            if calls_gate else
            "def dispatch(tool, args):\n"
            "    # silent-no-fire: the hook runner exists but nothing calls it\n"
            "    return None\n"
        )
        path = os.path.join(self._tmp.name, f"{name}.py")
        with open(path, "w") as fh:
            fh.write(textwrap.dedent(body))
        sys.modules.pop(name, None)
        return name

    def test_case_10_liveness_passes_when_the_hook_enforces(self):
        wired = self._write_module(f"wired_{uuid.uuid4().hex}", calls_gate=True)
        liveness_mod.DISPATCH_MODULES = (wired,)
        restore = self.hermes.install(sys.modules)
        self.addCleanup(restore)

        report = liveness_mod.run_liveness_check()
        self.assertTrue(report.ok, report.details())
        self.assertTrue(report.wiring_ok)
        self.assertTrue(report.enforce_ok)
        self.assertTrue(report.fault_ok)

    def test_case_11_liveness_FAILS_when_the_hook_never_fires(self):
        # The headline case. A build where the hook is registered successfully
        # and the dispatch path simply never calls the gate.
        unwired = self._write_module(f"unwired_{uuid.uuid4().hex}", calls_gate=False)
        liveness_mod.DISPATCH_MODULES = (unwired,)
        restore = self.hermes.install(sys.modules)
        self.addCleanup(restore)

        report = liveness_mod.run_liveness_check()
        self.assertFalse(report.ok)
        self.assertFalse(report.wiring_ok)
        self.assertIn(unwired, report.unwired_modules)
        self.assertIn("silent-no-fire", report.details())

    def test_case_11b_partial_wiring_is_also_a_failure(self):
        # Some paths gated, others not, is not a posture worth arming for.
        wired = self._write_module(f"w_{uuid.uuid4().hex}", calls_gate=True)
        unwired = self._write_module(f"u_{uuid.uuid4().hex}", calls_gate=False)
        liveness_mod.DISPATCH_MODULES = (wired, unwired)
        restore = self.hermes.install(sys.modules)
        self.addCleanup(restore)

        report = liveness_mod.run_liveness_check()
        self.assertFalse(report.wiring_ok)
        self.assertEqual(report.wired_modules, [wired])
        self.assertEqual(report.unwired_modules, [unwired])

    def test_enforce_probe_fails_when_nothing_blocks_the_canary(self):
        hermes = MockHermes()          # no plugin attached at all
        report = liveness_mod.LivenessReport()
        liveness_mod.check_enforce(report, plugins_module=_as_module(hermes))
        self.assertFalse(report.enforce_ok)
        self.assertIn("NOT blocked", report.details())

    def test_enforce_probe_fails_when_someone_else_blocks_the_canary(self):
        # An impostor blocking the canary must not be mistaken for interlock
        # enforcing. That would be exactly the false confidence this denies.
        hermes = MockHermes()
        hermes.hooks["pre_tool_call"] = [
            lambda **kw: {"action": "block", "message": "blocked by some other plugin"}
        ]
        report = liveness_mod.LivenessReport()
        liveness_mod.check_enforce(report, plugins_module=_as_module(hermes))
        self.assertFalse(report.enforce_ok)
        self.assertIn("other than interlock", report.details())

    def test_fault_probe_fails_when_an_internal_error_does_not_block(self):
        hermes = MockHermes()
        hermes.hooks["pre_tool_call"] = [lambda **kw: None]  # permits everything
        report = liveness_mod.LivenessReport()
        liveness_mod.check_fault(report, plugins_module=_as_module(hermes))
        self.assertFalse(report.fault_ok)
        self.assertIn("did NOT produce a block", report.details())

    def test_canary_never_reaches_the_pdp(self):
        # The probe must not depend on a live PDP, or liveness would be
        # untestable exactly when the PDP is down.
        plugin = InterlockHermesPlugin(socket_path="/definitely/not/a/socket")
        hermes = MockHermes()
        plugin.attach(hermes.context())
        message = hermes.resolve_pre_tool_block(CANARY_TOOL, {"mode": "enforce"})
        self.assertIn(CANARY_ENFORCE_TOKEN, message)

    def test_assert_live_raises_on_failure(self):
        unwired = self._write_module(f"x_{uuid.uuid4().hex}", calls_gate=False)
        liveness_mod.DISPATCH_MODULES = (unwired,)
        restore = self.hermes.install(sys.modules)
        self.addCleanup(restore)
        with self.assertRaises(liveness_mod.LivenessError):
            liveness_mod.assert_live()


def _as_module(mock):
    """Wrap a MockHermes so liveness can call it as a plugins module."""
    import types

    m = types.ModuleType("hermes_cli.plugins")
    m.resolve_pre_tool_block = mock.resolve_pre_tool_block
    m.invoke_hook = mock.invoke_hook
    return m


# ---------------------------------------------------------------------------
# Context mapping (H1.3).
# ---------------------------------------------------------------------------

class TestContextMapping(unittest.TestCase):

    def setUp(self):
        self.plugin = armed_plugin(socket_path="/nonexistent.sock")

    def test_prefers_hermes_ids_when_present(self):
        call = self.plugin.to_toolcall(
            tool_name="delete_file", args={"path": "/a"},
            session_id="hermes-sess-7", tool_call_id="hermes-call-9",
            turn_id="t1", task_id="k1", api_request_id="r1")
        self.assertEqual(call.session_id, "hermes-sess-7")
        self.assertEqual(call.call_id, "hermes-call-9")
        self.assertEqual(call.meta["turn_id"], "t1")
        self.assertEqual(call.meta["task_id"], "k1")
        self.assertEqual(call.meta["harness"], "hermes")

    def test_effect_is_always_none(self):
        call = self.plugin.to_toolcall(
            tool_name="delete_file", args={"path": "/a"},
            session_id="s", tool_call_id="c")
        self.assertIsNone(call.effect, "the PDP classifies, never the adapter")

    def test_session_id_falls_back_to_a_STABLE_process_identity(self):
        # An unattended run that never sets a session id still needs one stable
        # identity: that is what ties a runaway loop to a single subject in the
        # ledger. A fresh id per call would make every call a new agent.
        first = self.plugin.to_toolcall(
            tool_name="t", args={}, session_id="", tool_call_id="c1")
        second = self.plugin.to_toolcall(
            tool_name="t", args={}, session_id=None, tool_call_id="c2")
        self.assertEqual(first.session_id, second.session_id)
        self.assertTrue(first.session_id.startswith("hermes-"))

    def test_call_id_falls_back_to_a_FRESH_uuid_per_call(self):
        first = self.plugin.to_toolcall(
            tool_name="t", args={}, session_id="s", tool_call_id="")
        second = self.plugin.to_toolcall(
            tool_name="t", args={}, session_id="s", tool_call_id="")
        self.assertNotEqual(first.call_id, second.call_id)

    def test_non_dict_args_do_not_explode(self):
        call = self.plugin.to_toolcall(
            tool_name="t", args="not-a-dict", session_id="s", tool_call_id="c")
        self.assertEqual(call.args, {})


# ---------------------------------------------------------------------------
# End to end: the plugin against the real PDP over a real socket.
# ---------------------------------------------------------------------------

class TestAgainstRealService(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.sock_path = os.path.join(self._tmp.name, "interlock.sock")

        self.policy = Policy.from_dict(POLICY)
        self.ledger = GrantLedger(StateStore(), threading.Lock())
        pipe = FilterPipeline(
            [RateLimiter(self.policy.rate_limit_config()), GateKeeper()],
            self.ledger, self.policy, authorizer=None)
        self.server = service.make_server(self.sock_path, pipe)
        t = threading.Thread(target=lambda: self.server.serve_forever(0.02), daemon=True)
        t.start()

        def _shutdown():
            self.server.shutdown()
            self.server.server_close()
            t.join(timeout=2)

        self.addCleanup(_shutdown)

        self.hermes = MockHermes()
        self.plugin = armed_plugin(
            client=PdpClient(self.sock_path, timeout=5.0), socket_path=self.sock_path)
        self.plugin.attach(self.hermes.context())

    def block(self, tool, args, **kw):
        return self.hermes.resolve_pre_tool_block(tool, args, **kw)

    def test_passive_tool_is_permitted_by_the_pdp(self):
        self.assertIsNone(self.block("list_files", {}))

    def test_consequential_tool_holds_and_surfaces_elevation(self):
        message = self.block("delete_file", {"path": "/victim/1.txt"})
        self.assertIsNotNone(message)
        self.assertIn("fs:delete", message)
        self.assertIn("approval", message)

    def test_grant_permits_exactly_one_call(self):
        self.ledger.mint("fs:delete", {"path": "/victim/1.txt"}, uses=1, ttl=None,
                         granted_by="operator")
        self.assertIsNone(self.block("delete_file", {"path": "/victim/1.txt"}))
        self.assertIsNotNone(self.block("delete_file", {"path": "/victim/1.txt"}),
                             "single-use grant was double-spent")

    def test_runaway_loop_one_approval_one_execution(self):
        # The scenario the project exists for, driven through the Hermes hook:
        # 50 autonomous deletes, one approval, exactly one gets through.
        self.ledger.mint("fs:delete", {"path": "/victim/7.txt"}, uses=1, ttl=None,
                         granted_by="operator")
        results = [
            self.block("delete_file", {"path": f"/victim/{i}.txt"},
                       session_id="runaway", tool_call_id=f"c{i}")
            for i in range(50)
        ]
        permitted = [i for i, r in enumerate(results) if r is None]
        self.assertEqual(permitted, [7], f"expected only index 7 to pass, got {permitted}")

    def test_pdp_unreachable_blocks_every_call(self):
        self.server.shutdown()
        self.server.server_close()
        plugin = armed_plugin(client=PdpClient(self.sock_path, timeout=0.5),
                              socket_path=self.sock_path)
        hermes = MockHermes()
        plugin.attach(hermes.context())
        message = hermes.resolve_pre_tool_block("delete_file", {"path": "/a"})
        self.assertEqual(message, PDP_UNAVAILABLE_REASON)

    def test_client_declared_passive_effect_is_ignored(self):
        # A shim cannot talk a consequential tool into the passive lane.
        message = self.block("delete_file", {"path": "/a", "effect": "read"})
        self.assertIsNotNone(message)
        self.assertIn("fs:delete", message)

    def test_unclassified_tool_is_gated_by_default(self):
        # Default-deny by effect: a tool nobody classified is consequential.
        self.assertIsNotNone(self.block("some_unknown_tool", {"x": 1}))


if __name__ == "__main__":
    unittest.main()


class TestTypoedHookName(unittest.TestCase):
    """
    A one-character mistake in the hook name is silent-no-fire.

    The real PluginContext.register_hook warns on an unknown hook and stores it
    anyway. So a typo registers "successfully", never fires, and reports nothing
    — while the plugin's own state says it is attached. Only the liveness check
    can catch this, which is precisely why liveness drives Hermes's resolver
    instead of inspecting our own registration.
    """

    def test_typoed_hook_registers_silently_and_never_fires(self):
        hermes = MockHermes()
        plugin = armed_plugin(socket_path="/nonexistent.sock")
        hermes.context().register_hook("pre_tool_kall", plugin.on_pre_tool_call)

        self.assertTrue(hermes.hooks.get("pre_tool_kall"), "stored under the typo")
        self.assertIn("unknown hook", hermes.warnings[0])
        self.assertIsNone(
            hermes.resolve_pre_tool_block("delete_file", {"path": "/a"}),
            "a typo'd hook name means the tool executes ungated")

    def test_liveness_enforce_probe_catches_the_typo(self):
        hermes = MockHermes()
        plugin = armed_plugin(socket_path="/nonexistent.sock")
        hermes.context().register_hook("pre_tool_kall", plugin.on_pre_tool_call)

        report = liveness_mod.LivenessReport()
        liveness_mod.check_enforce(report, plugins_module=_as_module(hermes))
        self.assertFalse(report.enforce_ok)
        self.assertIn("NOT blocked", report.details())


class TestGateCompositionIsLoadBearing(unittest.TestCase):
    """
    Each probe must be able to fail the whole gate on its own.

    Found by mutation: deleting `fault_ok` from LivenessReport.ok survived the
    suite, because every fault test asserted on check_fault in isolation and
    none asserted that a failing fault probe blocks arming. A probe that cannot
    fail the gate is decoration.
    """

    def _report(self, wiring=True, enforce=True, fault=True):
        return liveness_mod.LivenessReport(
            wiring_ok=wiring, enforce_ok=enforce, fault_ok=fault)

    def test_all_three_pass_is_the_only_ok(self):
        self.assertTrue(self._report().ok)

    def test_each_probe_alone_fails_the_gate(self):
        for kw in ({"wiring": False}, {"enforce": False}, {"fault": False}):
            with self.subTest(**kw):
                self.assertFalse(self._report(**kw).ok)

    def test_a_hook_that_enforces_but_is_not_exception_proof_does_not_arm(self):
        # The realistic shape of the surviving mutant: a plugin that correctly
        # blocks the canary but lets an internal error through. Under Hermes
        # that plugin permits any tool call that trips a bug in its own code.
        hermes = MockHermes()

        def half_safe(**kwargs):
            if kwargs.get("args", {}).get("mode") == CANARY_MODE_FAULT:
                return None  # internal error -> no directive -> tool runs
            return {"action": "block", "message": CANARY_ENFORCE_TOKEN}

        hermes.hooks["pre_tool_call"] = [half_safe]
        module = _as_module(hermes)

        report = liveness_mod.LivenessReport()
        liveness_mod.check_enforce(report, plugins_module=module)
        liveness_mod.check_fault(report, plugins_module=module)
        report.wiring_ok = True

        self.assertTrue(report.enforce_ok, "enforce genuinely passes here")
        self.assertFalse(report.fault_ok)
        self.assertFalse(report.ok, "must not arm: not exception-proof")
