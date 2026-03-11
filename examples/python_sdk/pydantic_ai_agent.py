#!/usr/bin/env python3
"""PydanticAI Agent with Pilot Protocol integration.

This example demonstrates how to integrate Pilot Protocol into a PydanticAI agent,
giving it the ability to communicate with other agents over the Pilot network.

The agent has function tools that can:
- Discover peer agents by hostname
- Send messages to other agents
- Request tasks from other agents
- Subscribe to events from peers

This mirrors how OpenClaw uses pilotctl, but natively integrated into the
agent's tool system.

Prerequisites:
- pip install pydantic-ai pilotprotocol
- Build shared library: make sdk-lib
- Daemon running: pilotctl daemon start --hostname pydantic-agent
- Trusted peers configured
"""

import json
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pilotprotocol import Driver, PilotError


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

@dataclass
class PilotDependencies:
    """Agent dependencies injected into tools."""
    driver: Driver
    our_address: str
    our_hostname: str


# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------

class AgentResponse(BaseModel):
    """Response from the agent."""
    message: str = Field(description="Natural language response to user")
    action_taken: str | None = Field(
        default=None,
        description="Description of any pilot protocol action taken",
    )
    data: dict[str, Any] | None = Field(
        default=None,
        description="Any structured data returned from tools",
    )


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

agent = Agent(
    "openai:gpt-4",
    deps_type=PilotDependencies,
    result_type=AgentResponse,
    system_prompt=(
        "You are an AI agent connected to the Pilot Protocol network. "
        "You can discover and communicate with other agents. "
        "Use your tools to interact with the network when appropriate. "
        "Always be helpful and explain what you're doing."
    ),
)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@agent.tool
def discover_peer(
    ctx: RunContext[PilotDependencies],
    hostname: str,
) -> dict[str, Any]:
    """Discover a peer agent by hostname.

    Use this tool when the user asks about finding, discovering, or connecting
    to another agent by name.

    Args:
        hostname: The hostname of the peer agent to discover

    Returns:
        Information about the peer including address and node_id
    """
    try:
        result = ctx.deps.driver.resolve_hostname(hostname)
        return {
            "status": "success",
            "hostname": hostname,
            "address": result.get("address"),
            "node_id": result.get("node_id"),
            "message": f"Found peer {hostname} at {result.get('address')}",
        }
    except PilotError as e:
        return {
            "status": "error",
            "message": f"Could not find peer {hostname}: {e}",
            "hint": "Ensure mutual trust is established with this peer",
        }


@agent.tool
def send_message_to_peer(
    ctx: RunContext[PilotDependencies],
    hostname: str,
    message: str,
) -> dict[str, Any]:
    """Send a text message to another agent via Data Exchange (port 1001).

    Use this when the user asks to send a message, communicate with,
    or contact another agent.

    Args:
        hostname: The hostname of the target agent
        message: The message to send

    Returns:
        Confirmation of message sent
    """
    try:
        # Resolve peer
        peer_info = ctx.deps.driver.resolve_hostname(hostname)
        peer_addr = peer_info.get("address")

        # Pack text frame (type 0x01)
        msg_bytes = message.encode("utf-8")
        frame = bytearray(1 + len(msg_bytes))
        frame[0] = 0x01  # FRAME_TEXT
        frame[1:] = msg_bytes

        # Send via Data Exchange port
        ctx.deps.driver.send_to(f"{peer_addr}:1001", bytes(frame))

        return {
            "status": "success",
            "to": hostname,
            "message": f"Message sent to {hostname}",
            "bytes": len(frame),
        }
    except PilotError as e:
        return {
            "status": "error",
            "message": f"Failed to send message: {e}",
        }


@agent.tool
def request_task_from_peer(
    ctx: RunContext[PilotDependencies],
    hostname: str,
    task_description: str,
) -> dict[str, Any]:
    """Request another agent to perform a task.

    Use this when the user wants to delegate work to another agent.
    Requires sufficient polo score.

    Args:
        hostname: The hostname of the worker agent
        task_description: Description of the task to perform

    Returns:
        Task submission status and task_id
    """
    try:
        # Resolve peer
        peer_info = ctx.deps.driver.resolve_hostname(hostname)
        peer_addr = peer_info.get("address")

        # Open connection to Task Submit port (1003)
        with ctx.deps.driver.dial(f"{peer_addr}:1003") as conn:
            # Pack task submission (type 0x01 = TASK_SUBMIT)
            desc_bytes = task_description.encode("utf-8")
            frame = bytearray(1 + len(desc_bytes))
            frame[0] = 0x01
            frame[1:] = desc_bytes

            # Send task request
            conn.write(bytes(frame))

            # Wait for response
            data = conn.read(4096)
            if data:
                response = json.loads(data.decode("utf-8"))
                return {
                    "status": "success",
                    "task_id": response.get("task_id"),
                    "accepted": response.get("accepted"),
                    "message": response.get("message"),
                    "worker": hostname,
                }

            return {"status": "error", "message": "No response from worker"}

    except PilotError as e:
        return {
            "status": "error",
            "message": f"Failed to submit task: {e}",
            "hint": "Check your polo score and ensure trust is established",
        }


@agent.tool
def get_network_status(ctx: RunContext[PilotDependencies]) -> dict[str, Any]:
    """Get current network status and information about this agent.

    Use this when the user asks about the agent's status, identity,
    or current state on the network.

    Returns:
        Network status information
    """
    try:
        info = ctx.deps.driver.info()
        return {
            "status": "success",
            "our_address": info.get("address"),
            "our_hostname": info.get("hostname"),
            "node_id": info.get("node_id"),
            "peers": info.get("peers", 0),
            "connections": info.get("connections", 0),
            "polo_score": info.get("polo_score", 0),
            "uptime_seconds": info.get("uptime_secs", 0),
        }
    except PilotError as e:
        return {
            "status": "error",
            "message": f"Failed to get status: {e}",
        }


@agent.tool
def list_trusted_peers(ctx: RunContext[PilotDependencies]) -> dict[str, Any]:
    """List all agents we have mutual trust with.

    Use this when the user asks about available peers, who we can
    communicate with, or our trusted connections.

    Returns:
        List of trusted peer agents
    """
    try:
        result = ctx.deps.driver.trusted_peers()
        trusted = result.get("trusted", [])

        return {
            "status": "success",
            "count": len(trusted),
            "peers": [
                {
                    "hostname": p.get("hostname", "unknown"),
                    "address": p.get("address"),
                    "node_id": p.get("node_id"),
                }
                for p in trusted
            ],
        }
    except PilotError as e:
        return {
            "status": "error",
            "message": f"Failed to list peers: {e}",
        }


@agent.tool
def establish_trust_with_peer(
    ctx: RunContext[PilotDependencies],
    hostname: str,
    reason: str = "Agent collaboration request",
) -> dict[str, Any]:
    """Send a trust handshake request to another agent.

    Use this when the user wants to connect with a new agent that
    we don't have trust established with yet.

    Args:
        hostname: Hostname of the peer agent
        reason: Justification for the trust request

    Returns:
        Status of the handshake request
    """
    try:
        # Resolve to get node_id
        peer_info = ctx.deps.driver.resolve_hostname(hostname)
        node_id = peer_info.get("node_id")

        # Send handshake
        result = ctx.deps.driver.handshake(node_id, reason)

        return {
            "status": "success",
            "peer": hostname,
            "node_id": node_id,
            "message": "Trust request sent. Waiting for peer approval.",
            "details": result,
        }
    except PilotError as e:
        return {
            "status": "error",
            "message": f"Failed to send handshake: {e}",
        }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the PydanticAI agent with Pilot Protocol integration."""
    print("PydanticAI Agent with Pilot Protocol Integration")
    print("=" * 60)

    # Connect to Pilot Protocol daemon
    print("\nConnecting to Pilot Protocol daemon...")
    driver = Driver()

    # Get our identity
    info = driver.info()
    our_address = info.get("address")
    our_hostname = info.get("hostname", "unknown")

    print("✓ Connected")
    print(f"  Address:  {our_address}")
    print(f"  Hostname: {our_hostname}")
    print(f"  Peers:    {info.get('peers', 0)}")

    # Create dependencies
    deps = PilotDependencies(
        driver=driver,
        our_address=our_address,
        our_hostname=our_hostname,
    )

    print("\n" + "=" * 60)
    print("Agent ready! Try asking:")
    print('  - "What is my network status?"')
    print('  - "Discover the agent called worker-agent"')
    print('  - "Send a hello message to worker-agent"')
    print('  - "Request worker-agent to analyse some data"')
    print('  - "Who are my trusted peers?"')
    print("=" * 60)

    # Example interactions
    examples = [
        "What is my current status on the network?",
        "Who are my trusted peers?",
        "Discover the agent called worker-agent and send them a greeting",
    ]

    for query in examples:
        print(f"\n\n>>> User: {query}")
        print("-" * 60)

        try:
            result = agent.run_sync(query, deps=deps)
            response = result.data

            print(f"Agent: {response.message}")

            if response.action_taken:
                print(f"\nAction: {response.action_taken}")

            if response.data:
                print(f"\nData: {json.dumps(response.data, indent=2)}")

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

    # Interactive mode
    print("\n\n" + "=" * 60)
    print("Entering interactive mode. Type 'quit' to exit.")
    print("=" * 60)

    while True:
        try:
            query = input("\n>>> You: ").strip()

            if query.lower() in ("quit", "exit", "q"):
                break

            if not query:
                continue

            result = agent.run_sync(query, deps=deps)
            response = result.data

            print(f"\nAgent: {response.message}")

            if response.action_taken:
                print(f"\nAction: {response.action_taken}")

            if response.data:
                print(f"\nData: {json.dumps(response.data, indent=2)}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"\nError: {e}")

    print("\n\nShutting down...")
    driver.close()
    print("✓ Disconnected from Pilot Protocol")


if __name__ == "__main__":
    main()
