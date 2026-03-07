#!/usr/bin/env python3
"""Advanced PydanticAI multi-agent collaboration with Pilot Protocol.

This example demonstrates:
- Multiple specialised agents working together
- Agent-to-agent task delegation
- Event stream pub/sub for coordination
- Data exchange for sharing results
- Polo score management

Scenario: Research Assistant System
- Coordinator Agent: Receives user requests, delegates to specialists
- Researcher Agent: Searches for information, analyses data
- Summariser Agent: Synthesises research into readable summaries
- All agents communicate via Pilot Protocol

Prerequisites:
- pip install pydantic-ai pilotprotocol
- Build shared library: make sdk-lib
- Multiple daemons running (or use different hostnames)
- Mutual trust established between agents
"""

import json
import time
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pilotprotocol import Driver, PilotError


# ---------------------------------------------------------------------------
# Shared dependencies
# ---------------------------------------------------------------------------

@dataclass
class AgentContext:
    """Shared context for all agents."""
    driver: Driver
    hostname: str
    address: str
    role: Literal["coordinator", "researcher", "summariser"]


# ============================================================================
# COORDINATOR AGENT
# ============================================================================

class CoordinatorResponse(BaseModel):
    """Response from coordinator agent."""
    status: str = Field(description="Status of the operation")
    message: str = Field(description="Message to user")
    tasks_delegated: list[dict] = Field(
        default_factory=list,
        description="Tasks delegated to other agents",
    )
    results: dict | None = Field(
        default=None,
        description="Final results if available",
    )


coordinator_agent = Agent(
    "openai:gpt-4",
    deps_type=AgentContext,
    result_type=CoordinatorResponse,
    system_prompt=(
        "You are a coordinator agent in a research system. "
        "Break down user requests into tasks, delegate to specialist agents, "
        "and synthesise results. Available specialists: researcher, summariser."
    ),
)


@coordinator_agent.tool
def delegate_research_task(
    ctx: RunContext[AgentContext],
    researcher_hostname: str,
    query: str,
) -> dict:
    """Delegate a research query to a researcher agent.

    Args:
        researcher_hostname: Hostname of the researcher agent
        query: The research query to investigate
    """
    try:
        # Resolve researcher
        peer_info = ctx.deps.driver.resolve_hostname(researcher_hostname)
        peer_addr = peer_info["address"]

        # Submit task via stream connection to port 1003
        with ctx.deps.driver.dial(f"{peer_addr}:1003") as conn:
            task_desc = f"Research: {query}"
            desc_bytes = task_desc.encode("utf-8")
            frame = bytearray(1 + len(desc_bytes))
            frame[0] = 0x01  # TASK_SUBMIT
            frame[1:] = desc_bytes

            conn.write(bytes(frame))

            # Wait for response
            data = conn.read(4096)
            if data:
                response = json.loads(data.decode("utf-8"))
                return {
                    "status": "delegated",
                    "task_id": response.get("task_id"),
                    "worker": researcher_hostname,
                    "query": query,
                }

        return {"status": "error", "message": "No response"}

    except PilotError as e:
        return {"status": "error", "message": str(e)}


@coordinator_agent.tool
def request_summary(
    ctx: RunContext[AgentContext],
    summariser_hostname: str,
    content: str,
) -> dict:
    """Request a summariser agent to create a summary.

    Args:
        summariser_hostname: Hostname of the summariser agent
        content: Content to summarise
    """
    try:
        peer_info = ctx.deps.driver.resolve_hostname(summariser_hostname)
        peer_addr = peer_info["address"]

        # Send via Data Exchange as JSON
        task_data = {
            "type": "summary_request",
            "content": content,
            "from": ctx.deps.hostname,
        }
        json_bytes = json.dumps(task_data).encode("utf-8")
        frame = bytearray(1 + len(json_bytes))
        frame[0] = 0x02  # FRAME_JSON
        frame[1:] = json_bytes

        ctx.deps.driver.send_to(f"{peer_addr}:1001", bytes(frame))

        return {
            "status": "requested",
            "summariser": summariser_hostname,
            "bytes": len(frame),
        }
    except PilotError as e:
        return {"status": "error", "message": str(e)}


@coordinator_agent.tool
def publish_coordination_event(
    ctx: RunContext[AgentContext],
    topic: str,
    message: str,
) -> dict:
    """Publish a coordination event to all subscribed agents.

    Args:
        topic: Event topic (e.g., "task.started", "task.completed")
        message: Event message
    """
    try:
        topic_bytes = topic.encode("utf-8")
        msg_bytes = message.encode("utf-8")
        frame = bytearray(2 + len(topic_bytes) + len(msg_bytes))
        frame[0:2] = len(topic_bytes).to_bytes(2, "big")
        frame[2 : 2 + len(topic_bytes)] = topic_bytes
        frame[2 + len(topic_bytes) :] = msg_bytes

        ctx.deps.driver.send_to(f"{ctx.deps.address}:1002", bytes(frame))

        return {"status": "published", "topic": topic}
    except PilotError as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# RESEARCHER AGENT
# ============================================================================

class ResearcherResponse(BaseModel):
    """Response from researcher agent."""
    status: str
    findings: str | None = None
    sources: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


researcher_agent = Agent(
    "openai:gpt-4",
    deps_type=AgentContext,
    result_type=ResearcherResponse,
    system_prompt=(
        "You are a research specialist agent. You analyse queries, "
        "search for information, and provide detailed findings. "
        "Always cite sources and provide confidence scores."
    ),
)


@researcher_agent.tool
def send_research_results(
    ctx: RunContext[AgentContext],
    coordinator_hostname: str,
    results: str,
) -> dict:
    """Send research results back to coordinator.

    Args:
        coordinator_hostname: Hostname of the coordinator
        results: Research findings to send
    """
    try:
        peer_info = ctx.deps.driver.resolve_hostname(coordinator_hostname)
        peer_addr = peer_info["address"]

        # Send as JSON via Data Exchange
        data = {
            "type": "research_results",
            "findings": results,
            "from": ctx.deps.hostname,
            "timestamp": time.time(),
        }
        json_bytes = json.dumps(data).encode("utf-8")
        frame = bytearray(1 + len(json_bytes))
        frame[0] = 0x02  # FRAME_JSON
        frame[1:] = json_bytes

        ctx.deps.driver.send_to(f"{peer_addr}:1001", bytes(frame))

        return {"status": "sent", "bytes": len(frame)}
    except PilotError as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# SUMMARISER AGENT
# ============================================================================

class SummariserResponse(BaseModel):
    """Response from summariser agent."""
    status: str
    summary: str | None = None
    key_points: list[str] = Field(default_factory=list)
    word_count: int = 0


summariser_agent = Agent(
    "openai:gpt-4",
    deps_type=AgentContext,
    result_type=SummariserResponse,
    system_prompt=(
        "You are a summarisation specialist. Create concise, clear summaries "
        "that capture key points while maintaining accuracy. "
        "Always extract and list key points separately."
    ),
)


@summariser_agent.tool
def send_summary_results(
    ctx: RunContext[AgentContext],
    recipient_hostname: str,
    summary: str,
) -> dict:
    """Send summary back to requesting agent.

    Args:
        recipient_hostname: Hostname of requesting agent
        summary: The summary text
    """
    try:
        peer_info = ctx.deps.driver.resolve_hostname(recipient_hostname)
        peer_addr = peer_info["address"]

        data = {
            "type": "summary_results",
            "summary": summary,
            "from": ctx.deps.hostname,
            "timestamp": time.time(),
        }
        json_bytes = json.dumps(data).encode("utf-8")
        frame = bytearray(1 + len(json_bytes))
        frame[0] = 0x02  # FRAME_JSON
        frame[1:] = json_bytes

        ctx.deps.driver.send_to(f"{peer_addr}:1001", bytes(frame))

        return {"status": "sent"}
    except PilotError as e:
        return {"status": "error", "message": str(e)}


# ============================================================================
# DEMO ORCHESTRATION
# ============================================================================

def demo_collaborative_workflow() -> None:
    """Demonstrate multi-agent collaboration."""
    print("Multi-Agent Research System Demo")
    print("=" * 70)

    # For demo, use single daemon with role differentiation
    # In production, each agent would run its own daemon

    print("\n1. Connecting coordinator agent...")
    coordinator_driver = Driver()
    coord_info = coordinator_driver.info()

    coordinator_ctx = AgentContext(
        driver=coordinator_driver,
        hostname=coord_info.get("hostname", "coordinator"),
        address=coord_info.get("address"),
        role="coordinator",
    )

    print(f"   ✓ Coordinator ready: {coordinator_ctx.hostname}")

    # Demo query
    user_query = (
        "Research the impact of transformer architectures on natural language "
        "processing and provide a summary of key findings."
    )

    print(f"\n2. User Query:")
    print(f"   {user_query}")

    print("\n3. Coordinator processing...")
    result = coordinator_agent.run_sync(user_query, deps=coordinator_ctx)
    response = result.data

    print(f"\n4. Coordinator Response:")
    print(f"   Status: {response.status}")
    print(f"   Message: {response.message}")

    if response.tasks_delegated:
        print(f"\n5. Tasks Delegated:")
        for task in response.tasks_delegated:
            print(f"   - {task}")

    print("\n6. Workflow Complete")
    print(f"   Polo Score: {coord_info.get('polo_score', 0)}")

    coordinator_driver.close()


def main() -> None:
    """Run the multi-agent demo."""
    print("\nPydanticAI Multi-Agent Collaboration with Pilot Protocol")
    print("=" * 70)
    print("\nThis demo shows how multiple specialised agents can collaborate")
    print("using Pilot Protocol for communication and coordination.")
    print("\nNote: For a full demo, run multiple daemons with different hostnames")
    print("and establish trust between them.")
    print("=" * 70)

    try:
        demo_collaborative_workflow()
    except PilotError as e:
        print(f"\n✗ Pilot error: {e}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
