"""
End-to-end: the REAL JS OpenClaw PEP (mock harness) driving the REAL Python PDP
over a REAL unix socket. Reproduces the §9 / Yue runaway and proves it is
structurally stopped by single-use grants.

Requires node (skipped otherwise). The Python side owns the ledger, so the
"operator" mint is a direct ledger call on the single-writer process — the
faithful representation of a same-host control path (a cross-process operator
CLI would require the single-writer store, which is deferred).
"""

import json
import os
import shutil
import subprocess
import threading
import tempfile
import unittest

from interlock import service
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore

NODE = shutil.which("node")
AGENT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "interlock", "adapters", "openclaw", "agent.mjs")
)

POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send", "list_inbox": "read"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},   # deferred mode: HOLD, no auto-approve
    "rate_limits": {"key": "session_effect", "default": None, "per_effect": {}},
}


@unittest.skipUnless(NODE, "node not available")
class TestEndToEndRunaway(unittest.TestCase):
    def _agent(self, sock, session, items):
        proc = subprocess.run(
            [NODE, AGENT, "--socket", sock, "--session", session, "--items", items, "--timeout", "2000"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"agent failed: {proc.stderr}")
        return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]

    def test_single_grant_stops_the_runaway(self):
        policy = Policy.from_dict(POLICY)
        ledger = GrantLedger(StateStore(), threading.Lock())
        pipe = FilterPipeline(
            [RateLimiter(policy.rate_limit_config()), GateKeeper()],
            ledger, policy, authorizer=None,  # deferred HOLD
        )
        with tempfile.TemporaryDirectory() as d:
            sock = os.path.join(d, "interlock.sock")
            server = service.make_server(sock, pipe)
            t = threading.Thread(target=lambda: server.serve_forever(0.02), daemon=True)
            t.start()
            try:
                # Phase 1 — runaway attempt: the agent tries to delete 1,2,3.
                # No grants exist, so every delete is HELD -> blocked.
                phase1 = self._agent(sock, "agent-1", "1,2,3")
                self.assertEqual([r["outcome"] for r in phase1], ["block", "block", "block"])
                self.assertIn("email:send", phase1[0]["reason"])  # elevation surfaced

                # Operator approves ONE action: mint one single-use grant for id 1.
                ledger.mint("email:send", {"id": 1}, uses=1, ttl=None, granted_by="operator")

                # Phase 2 — the agent re-issues and keeps looping: 1, 1 again, 2.
                phase2 = self._agent(sock, "agent-1", "1,1,2")
                outcomes = [r["outcome"] for r in phase2]
                self.assertEqual(outcomes.count("allow"), 1)      # exactly one delete succeeds
                self.assertEqual(phase2[0]["outcome"], "allow")   # the approved id 1, once
                self.assertEqual(phase2[1]["outcome"], "block")   # single-use grant already spent
                self.assertEqual(phase2[2]["outcome"], "block")   # id 2 was never approved

                # The grant is gone; a third run finds nothing to consume.
                phase3 = self._agent(sock, "agent-1", "1")
                self.assertEqual(phase3[0]["outcome"], "block")
            finally:
                server.shutdown()
                server.server_close()
                service._safe_unlink(sock)


if __name__ == "__main__":
    unittest.main()
