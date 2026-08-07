# Managed node SDK boundary

This directory is the public, node-side half of Pilot's optional managed mode.
It contains signed wire contracts, local verification, deterministic policy
enforcement, rollout/fleet clients, and one-time adoption support needed by
`pilotctl` and `pilot-daemon`.

It does **not** contain the hosted platform's tenant services, persistence,
semantic evaluator, billing, management UI, or account infrastructure. Those
remain in the private hosted-platform repository.

It is also independent of `pilotprotocol-mcp`. The MCP package is an optional
harness adapter; it neither installs nor owns Pilot's node identity, managed
attachment, daemon, policy state, or fleet-control channel.
