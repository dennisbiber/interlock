"""
interlock — a passive policy-enforcement layer (PDP) for agent tool calls.

Interception happens at the tool-execution boundary, never at user input, so it
gates autonomous loops, spawned sub-agents, and unattended jobs — not just
interactive requests. See the design plan (filter_layer_plan.md) for the full
architecture. This package is being built in phases P0..P5; P0 is the core
types and the grant ledger.
"""

__version__ = "0.0.0"
