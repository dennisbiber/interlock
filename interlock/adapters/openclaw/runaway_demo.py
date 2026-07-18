"""
runaway_demo.py — the whole point of interlock, demonstrated.

Reproduces the §9 / Yue scenario: an autonomous OpenClaw agent tries to delete a
pile of emails. Without a per-action gate, a "confirm first" instruction lost to
context compaction lets it delete hundreds. With interlock, every delete hits the
tool-execution boundary; the first is HELD pending approval; a human approves ONE;
exactly one delete proceeds; the loop's next deletes are HELD again.

Run from the repo root:
    python interlock/adapters/openclaw/runaway_demo.py
"""

import json
import os
import shutil
import subprocess
import threading
import tempfile

from interlock import service
from interlock.filters.gatekeeper import GateKeeper
from interlock.filters.rate_limiter import RateLimiter
from interlock.ledger import GrantLedger
from interlock.pipeline import FilterPipeline, Policy
from interlock.store.state_store import StateStore

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent.mjs")
POLICY = {
    "passive_effects": ["read", "list"],
    "tool_effects": {"delete_email": "email:send"},
    "tool_scopes": {"delete_email": ["id"]},
    "elevation": {"default": "HumanApprover"},
    "rate_limits": {"key": "session_effect", "default": None, "per_effect": {}},
}


def run_agent(sock, session, items):
    node = shutil.which("node")
    proc = subprocess.run(
        [node, AGENT, "--socket", sock, "--session", session, "--items", items, "--timeout", "2000"],
        capture_output=True, text=True, timeout=30,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def show(rows):
    for r in rows:
        mark = "✓ deleted" if r["outcome"] == "allow" else "✗ BLOCKED"
        extra = "" if r["outcome"] == "allow" else f"  ({r['reason'].split('.')[0]})"
        print(f"    email #{r['item']}: {mark}{extra}")


def main():
    if not shutil.which("node"):
        print("node is required for this demo"); return
    policy = Policy.from_dict(POLICY)
    ledger = GrantLedger(StateStore(), threading.Lock())
    pipe = FilterPipeline([RateLimiter(policy.rate_limit_config()), GateKeeper()],
                          ledger, policy, authorizer=None)

    with tempfile.TemporaryDirectory() as d:
        sock = os.path.join(d, "interlock.sock")
        server = service.make_server(sock, pipe)
        threading.Thread(target=lambda: server.serve_forever(0.02), daemon=True).start()
        try:
            print("\nPDP listening on", sock, "(single process, owner-only)\n")
            print("1) Autonomous agent goes rogue and tries to delete emails 1..5:")
            show(run_agent(sock, "yue-agent", "1,2,3,4,5"))
            print("\n   -> Every destructive call was blocked at the execution boundary.")
            print("      A compacted-away 'confirm first' rule can't reopen this: the gate")
            print("      is on execution, not on the prompt.\n")

            print("2) A human reviews the hold and approves exactly ONE deletion (email #1).")
            print("   Operator mints a single-use, item-scoped grant:\n")
            ledger.mint("email:send", {"id": 1}, uses=1, ttl=None, granted_by="human:yue")

            print("3) The agent resumes its loop — retry #1, then keep deleting (1 again, 2):")
            show(run_agent(sock, "yue-agent", "1,1,2"))
            print("\n   -> Exactly one delete succeeded (the approved email #1, once).")
            print("      The single-use grant was spent immediately; the very next delete —")
            print("      even of the same email — is blocked again, and so is email #2.\n")

            print("A runaway destructive loop is structurally impossible without a fresh")
            print("human approval per action. That is the whole point.\n")
        finally:
            server.shutdown()
            server.server_close()
            service._safe_unlink(sock)


if __name__ == "__main__":
    main()
