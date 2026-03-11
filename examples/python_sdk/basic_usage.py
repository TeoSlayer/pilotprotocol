#!/usr/bin/env python3
"""Basic usage examples for the Pilot Protocol Python SDK.

This script demonstrates:
- Connecting to the daemon
- Getting node info
- Setting hostname
- Resolving peer hostnames
- Establishing trust (handshake/approve)
- Listing trusted peers and pending requests

Prerequisites:
- Build shared library: make sdk-lib
- Daemon must be running: pilotctl daemon start --hostname my-agent
"""

import sys
from pilotprotocol import Driver, PilotError


def show_info(driver: Driver) -> None:
    """Display current node information."""
    print("\n=== Node Info ===")
    info = driver.info()
    print(f"Address:     {info.get('address')}")
    print(f"Node ID:     {info.get('node_id')}")
    print(f"Hostname:    {info.get('hostname', '(not set)')}")
    print(f"Peers:       {info.get('peers', 0)}")
    print(f"Connections: {info.get('connections', 0)}")
    print(f"Uptime:      {info.get('uptime_secs', 0)}s")


def set_hostname_example(driver: Driver, hostname: str) -> None:
    """Set the node's hostname."""
    print(f"\n=== Setting Hostname: {hostname} ===")
    result = driver.set_hostname(hostname)
    print(f"Result: {result}")


def resolve_hostname_example(driver: Driver, hostname: str) -> dict:
    """Resolve a peer's hostname to address and node_id."""
    print(f"\n=== Resolving Hostname: {hostname} ===")
    try:
        result = driver.resolve_hostname(hostname)
        print(f"Node ID:  {result.get('node_id')}")
        print(f"Address:  {result.get('address')}")
        return result
    except PilotError as e:
        print(f"Failed to resolve: {e}")
        print("Hint: Ensure mutual trust is established")
        return {}


def handshake_example(driver: Driver, node_id: int, justification: str) -> None:
    """Send a trust handshake request to a peer."""
    print(f"\n=== Sending Handshake to Node {node_id} ===")
    print(f"Justification: {justification}")
    try:
        result = driver.handshake(node_id, justification)
        print(f"Result: {result}")
        print("Handshake request sent. Wait for peer to approve.")
    except PilotError as e:
        print(f"Handshake failed: {e}")


def pending_handshakes_example(driver: Driver) -> list:
    """List pending trust requests."""
    print("\n=== Pending Trust Requests ===")
    result = driver.pending_handshakes()
    pending = result.get("pending", [])

    if not pending:
        print("No pending requests")
        return []

    for req in pending:
        print(f"Node ID:        {req.get('node_id')}")
        print(f"Address:        {req.get('address')}")
        print(f"Justification:  {req.get('justification', '(none)')}")
        print(f"Received:       {req.get('timestamp', 'unknown')}")
        print("---")

    return pending


def approve_handshake_example(driver: Driver, node_id: int) -> None:
    """Approve a pending trust request."""
    print(f"\n=== Approving Node {node_id} ===")
    try:
        result = driver.approve_handshake(node_id)
        print(f"Result: {result}")
        print("Trust established!")
    except PilotError as e:
        print(f"Approval failed: {e}")


def list_trusted_peers(driver: Driver) -> None:
    """List all mutually trusted peers."""
    print("\n=== Trusted Peers ===")
    result = driver.trusted_peers()
    trusted = result.get("trusted", [])

    if not trusted:
        print("No trusted peers yet")
        return

    for peer in trusted:
        print(f"Node ID:   {peer.get('node_id')}")
        print(f"Address:   {peer.get('address')}")
        print(f"Hostname:  {peer.get('hostname', '(none)')}")
        print("---")


def set_visibility_example(driver: Driver, public: bool) -> None:
    """Set node visibility (public or private)."""
    visibility = "public" if public else "private"
    print(f"\n=== Setting Visibility: {visibility} ===")
    result = driver.set_visibility(public)
    print(f"Result: {result}")


def set_tags_example(driver: Driver, tags: list[str]) -> None:
    """Set capability tags for the node."""
    print(f"\n=== Setting Tags: {', '.join(tags)} ===")
    result = driver.set_tags(tags)
    print(f"Result: {result}")


def main() -> None:
    """Run basic usage examples."""
    print("Pilot Protocol Python SDK — Basic Usage Examples")
    print("=" * 60)

    # Connect to daemon
    print("\nConnecting to daemon...")
    try:
        with Driver() as driver:
            print("✓ Connected")

            # Show current info
            show_info(driver)

            # Set hostname if not already set
            set_hostname_example(driver, "python-demo-agent")

            # Set tags
            set_tags_example(driver, ["python", "demo", "sdk"])

            # Set to private mode (default)
            set_visibility_example(driver, False)

            # List trusted peers
            list_trusted_peers(driver)

            # List pending handshakes
            pending = pending_handshakes_example(driver)

            # Interactive examples (commented out by default)
            # Uncomment and customise for your use case:

            # Example: Resolve a peer's hostname
            # peer = resolve_hostname_example(driver, "other-agent")

            # Example: Send trust request to a peer
            # if peer:
            #     peer_id = peer.get("node_id")
            #     handshake_example(driver, peer_id, "SDK demo collaboration")

            # Example: Approve a pending request
            # if pending:
            #     approve_handshake_example(driver, pending[0]["node_id"])

            print("\n" + "=" * 60)
            print("✓ Basic usage examples completed")
            print("\nNext steps:")
            print("- Run data_exchange_demo.py for file/message transfer")
            print("- Run event_stream_demo.py for pub/sub patterns")
            print("- Run task_submit_demo.py for task execution")

    except PilotError as e:
        print(f"\n✗ Failed to connect to daemon: {e}")
        print("\nHint: Start the daemon first:")
        print("  pilotctl daemon start --hostname my-agent")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
