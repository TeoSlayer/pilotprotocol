#!/usr/bin/env python3
"""Event Stream service demo using Pilot Protocol Python SDK.

The Event Stream service (port 1002) provides pub/sub messaging with:
- Topic-based routing
- Wildcard subscriptions (*)
- Real-time event delivery
- Multiple subscribers per topic

Prerequisites:
- Build shared library: make sdk-lib
- Daemon running: pilotctl daemon start --hostname publisher-agent
- Target peer: Must have mutual trust established
"""

import json
import sys
import time
import threading
from pilotprotocol import Driver, PilotError


# Event Stream port
EVENT_STREAM_PORT = 1002


def pack_event(topic: str, message: str) -> bytes:
    """Pack an event into Event Stream format.

    Format: [topic_len:2][topic][message]
    """
    topic_bytes = topic.encode("utf-8")
    message_bytes = message.encode("utf-8")

    if len(topic_bytes) > 65535:
        raise ValueError("Topic too long")

    frame = bytearray(2 + len(topic_bytes) + len(message_bytes))
    frame[0:2] = len(topic_bytes).to_bytes(2, "big")
    frame[2 : 2 + len(topic_bytes)] = topic_bytes
    frame[2 + len(topic_bytes) :] = message_bytes

    return bytes(frame)


def publish_event(driver: Driver, peer_addr: str, topic: str, message: str) -> None:
    """Publish an event to a peer's event stream broker."""
    print(f"Publishing: {topic} -> {message}")
    frame = pack_event(topic, message)
    driver.send_to(f"{peer_addr}:{EVENT_STREAM_PORT}", frame)


def subscribe_and_listen(driver: Driver, peer_addr: str, topic: str, duration: int = 30) -> None:
    """Subscribe to events from a peer.

    Opens a stream connection to the peer's event stream broker,
    sends a subscription frame, then listens for events.
    """
    print(f"\n=== Subscribing to Topic: {topic} ===")
    print(f"Peer:     {peer_addr}:{EVENT_STREAM_PORT}")
    print(f"Duration: {duration}s")

    # Open stream to event stream port
    with driver.dial(f"{peer_addr}:{EVENT_STREAM_PORT}") as conn:
        print("✓ Connected")

        # Send subscription frame (same format as publish)
        sub_frame = pack_event(topic, "")
        conn.write(sub_frame)
        print(f"✓ Subscribed to: {topic}")

        # Listen for events
        print("\nWaiting for events...")
        print("-" * 40)

        start_time = time.time()
        event_count = 0

        while time.time() - start_time < duration:
            try:
                data = conn.read(4096)
                if not data:
                    break

                # Parse event frame
                if len(data) < 2:
                    continue

                topic_len = int.from_bytes(data[0:2], "big")
                if len(data) < 2 + topic_len:
                    continue

                received_topic = data[2 : 2 + topic_len].decode("utf-8")
                message = data[2 + topic_len :].decode("utf-8")

                event_count += 1
                timestamp = time.strftime("%H:%M:%S")
                print(f"[{timestamp}] {received_topic}: {message}")

            except PilotError:
                # Read timeout or connection closed
                break
            except Exception as e:
                print(f"Parse error: {e}")
                continue

        print("-" * 40)
        print(f"✓ Received {event_count} events in {duration}s")


def publish_sequence(driver: Driver, peer_addr: str, topic: str, count: int = 10, interval: float = 1.0) -> None:
    """Publish a sequence of events."""
    print(f"\n=== Publishing Event Sequence ===")
    print(f"Topic:    {topic}")
    print(f"Count:    {count}")
    print(f"Interval: {interval}s")

    for i in range(count):
        message = json.dumps(
            {
                "sequence": i + 1,
                "timestamp": time.time(),
                "data": f"Event {i + 1} of {count}",
            }
        )

        publish_event(driver, peer_addr, topic, message)
        print(f"  [{i + 1}/{count}] Published")

        if i < count - 1:
            time.sleep(interval)

    print("✓ Sequence complete")


def demo_wildcard_subscription(driver: Driver, peer_addr: str) -> None:
    """Demo wildcard subscription listening to all topics."""
    print("\n=== Wildcard Subscription Demo ===")
    print("Subscribing to: * (all topics)")

    # Start subscriber in a thread
    sub_thread = threading.Thread(
        target=subscribe_and_listen,
        args=(driver, peer_addr, "*", 15),
        daemon=True,
    )
    sub_thread.start()

    # Wait for subscription to establish
    time.sleep(2)

    # Publish events to multiple topics
    topics = ["status", "metrics", "alerts", "logs"]
    for i, topic in enumerate(topics):
        publish_event(driver, peer_addr, topic, f"Test message for {topic} (#{i + 1})")
        time.sleep(0.5)

    # Wait for subscriber to finish
    sub_thread.join(timeout=20)


def demo_topic_filtering(driver: Driver, peer_addr: str) -> None:
    """Demo topic-specific subscription."""
    print("\n=== Topic Filtering Demo ===")

    # Start subscriber in a thread
    sub_thread = threading.Thread(
        target=subscribe_and_listen,
        args=(driver, peer_addr, "alerts", 10),
        daemon=True,
    )
    sub_thread.start()

    time.sleep(2)

    # Publish to multiple topics — subscriber should only see "alerts"
    publish_event(driver, peer_addr, "status", "This won't be received")
    time.sleep(0.5)

    publish_event(driver, peer_addr, "alerts", "HIGH PRIORITY: System alert!")
    time.sleep(0.5)

    publish_event(driver, peer_addr, "metrics", "This won't be received either")
    time.sleep(0.5)

    publish_event(driver, peer_addr, "alerts", "MEDIUM: Resource usage spike")

    sub_thread.join(timeout=15)


def main() -> None:
    """Run Event Stream demos."""
    print("Pilot Protocol Python SDK — Event Stream Demo")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python event_stream_demo.py <peer-address|hostname> [mode]")
        print("\nModes:")
        print("  publish   — Publish a sequence of events (default)")
        print("  subscribe — Subscribe and listen for events")
        print("  wildcard  — Subscribe to all topics (*)")
        print("  filter    — Demo topic-specific filtering")
        print("\nExamples:")
        print("  python event_stream_demo.py other-agent publish")
        print("  python event_stream_demo.py 0:0000.0000.0005 subscribe")
        print("\nPrerequisites:")
        print("  1. Build library:  make sdk-lib")
        print("  2. Start daemon:   pilotctl daemon start --hostname my-agent")
        print("  3. Establish trust: pilotctl handshake other-agent")
        sys.exit(1)

    peer = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "publish"

    print(f"\nTarget peer: {peer}")
    print(f"Mode: {mode}")

    try:
        with Driver() as driver:
            print("✓ Connected to daemon")

            info = driver.info()
            print(f"Our address: {info.get('address')}")

            # Resolve peer hostname if needed
            peer_addr = peer
            if ":" not in peer:
                print(f"\nResolving hostname: {peer}")
                result = driver.resolve_hostname(peer)
                peer_addr = result.get("address")
                print(f"Resolved to: {peer_addr}")

            if mode == "publish":
                publish_sequence(driver, peer_addr, "demo.events", count=10, interval=0.5)

            elif mode == "subscribe":
                topic = sys.argv[3] if len(sys.argv) > 3 else "demo.events"
                subscribe_and_listen(driver, peer_addr, topic, duration=30)

            elif mode == "wildcard":
                demo_wildcard_subscription(driver, peer_addr)

            elif mode == "filter":
                demo_topic_filtering(driver, peer_addr)

            else:
                print(f"✗ Unknown mode: {mode}")
                sys.exit(1)

            print("\n" + "=" * 60)
            print("✓ Event Stream demo completed")

    except PilotError as e:
        print(f"\n✗ Pilot error: {e}")
        print("\nHint: Start the daemon first:")
        print("  pilotctl daemon start --hostname my-agent")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
