#!/usr/bin/env python3
"""Data Exchange service demo using Pilot Protocol Python SDK.

The Data Exchange service (port 1001) provides typed frame protocol for:
- Text messages
- JSON objects
- Binary data
- File transfers

All transfers include ACKs and are persisted to ~/.pilot/inbox/ and ~/.pilot/received/

Prerequisites:
- Build shared library: make sdk-lib
- Daemon running: pilotctl daemon start --hostname sender-agent
- Target peer: Must have mutual trust established
"""

import json
import sys
import time
from pathlib import Path
from pilotprotocol import Driver, PilotError


# Data Exchange port
DATA_EXCHANGE_PORT = 1001

# Frame types (matches Go implementation in pkg/dataexchange/)
FRAME_TEXT = 0x01
FRAME_JSON = 0x02
FRAME_BINARY = 0x03
FRAME_FILE = 0x04
FRAME_ACK = 0x10


def pack_text_frame(message: str) -> bytes:
    """Pack a text message into a Data Exchange frame."""
    msg_bytes = message.encode("utf-8")
    frame = bytearray(1 + len(msg_bytes))
    frame[0] = FRAME_TEXT
    frame[1:] = msg_bytes
    return bytes(frame)


def pack_json_frame(data: dict) -> bytes:
    """Pack a JSON object into a Data Exchange frame."""
    json_bytes = json.dumps(data).encode("utf-8")
    frame = bytearray(1 + len(json_bytes))
    frame[0] = FRAME_JSON
    frame[1:] = json_bytes
    return bytes(frame)


def pack_binary_frame(data: bytes) -> bytes:
    """Pack binary data into a Data Exchange frame."""
    frame = bytearray(1 + len(data))
    frame[0] = FRAME_BINARY
    frame[1:] = data
    return bytes(frame)


def pack_file_frame(filename: str, content: bytes) -> bytes:
    """Pack a file into a Data Exchange frame.

    Format: [FRAME_FILE][filename_len:2][filename][content]
    """
    filename_bytes = filename.encode("utf-8")
    if len(filename_bytes) > 65535:
        raise ValueError("Filename too long")

    frame = bytearray(1 + 2 + len(filename_bytes) + len(content))
    frame[0] = FRAME_FILE
    frame[1:3] = len(filename_bytes).to_bytes(2, "big")
    frame[3 : 3 + len(filename_bytes)] = filename_bytes
    frame[3 + len(filename_bytes) :] = content
    return bytes(frame)


def send_text_message(driver: Driver, peer_addr: str, message: str) -> None:
    """Send a text message via Data Exchange."""
    print(f"\n=== Sending Text Message ===")
    print(f"To:      {peer_addr}:{DATA_EXCHANGE_PORT}")
    print(f"Message: {message}")

    frame = pack_text_frame(message)
    driver.send_to(f"{peer_addr}:{DATA_EXCHANGE_PORT}", frame)

    print("✓ Text message sent")
    print("Target will receive in: ~/.pilot/inbox/")


def send_json_message(driver: Driver, peer_addr: str, data: dict) -> None:
    """Send a JSON object via Data Exchange."""
    print(f"\n=== Sending JSON Message ===")
    print(f"To:   {peer_addr}:{DATA_EXCHANGE_PORT}")
    print(f"Data: {json.dumps(data, indent=2)}")

    frame = pack_json_frame(data)
    driver.send_to(f"{peer_addr}:{DATA_EXCHANGE_PORT}", frame)

    print("✓ JSON message sent")


def send_file(driver: Driver, peer_addr: str, filepath: Path) -> None:
    """Send a file via Data Exchange."""
    print(f"\n=== Sending File ===")
    print(f"To:   {peer_addr}:{DATA_EXCHANGE_PORT}")
    print(f"File: {filepath}")

    if not filepath.exists():
        print(f"✗ File not found: {filepath}")
        return

    content = filepath.read_bytes()
    print(f"Size: {len(content)} bytes")

    frame = pack_file_frame(filepath.name, content)
    driver.send_to(f"{peer_addr}:{DATA_EXCHANGE_PORT}", frame)

    print("✓ File sent")
    print(f"Target will receive in: ~/.pilot/received/{filepath.name}")


def send_binary_data(driver: Driver, peer_addr: str, data: bytes) -> None:
    """Send raw binary data via Data Exchange."""
    print(f"\n=== Sending Binary Data ===")
    print(f"To:   {peer_addr}:{DATA_EXCHANGE_PORT}")
    print(f"Size: {len(data)} bytes")

    frame = pack_binary_frame(data)
    driver.send_to(f"{peer_addr}:{DATA_EXCHANGE_PORT}", frame)

    print("✓ Binary data sent")


def main() -> None:
    """Run Data Exchange demo."""
    print("Pilot Protocol Python SDK — Data Exchange Demo")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage: python data_exchange_demo.py <peer-address|hostname>")
        print("\nExamples:")
        print("  python data_exchange_demo.py other-agent")
        print("  python data_exchange_demo.py 0:0000.0000.0005")
        print("\nPrerequisites:")
        print("  1. Build library:  make sdk-lib")
        print("  2. Start daemon:   pilotctl daemon start --hostname sender-agent")
        print("  3. Establish trust: pilotctl handshake other-agent")
        sys.exit(1)

    peer = sys.argv[1]
    print(f"\nTarget peer: {peer}")

    try:
        with Driver() as driver:
            print("✓ Connected to daemon")

            info = driver.info()
            print(f"Our address: {info.get('address')}")

            # Resolve peer hostname to address if needed
            peer_addr = peer
            if ":" not in peer:
                print(f"\nResolving hostname: {peer}")
                result = driver.resolve_hostname(peer)
                peer_addr = result.get("address")
                print(f"Resolved to: {peer_addr}")

            # Example 1: Send text message
            send_text_message(
                driver,
                peer_addr,
                "Hello from Python SDK! This is a text message.",
            )

            time.sleep(0.5)

            # Example 2: Send JSON message
            send_json_message(
                driver,
                peer_addr,
                {
                    "type": "status_update",
                    "status": "online",
                    "timestamp": "2026-03-03T10:00:00Z",
                    "metrics": {"cpu": 45.2, "memory": 1024},
                },
            )

            time.sleep(0.5)

            # Example 3: Send binary data
            binary_data = bytes([0x48, 0x65, 0x6C, 0x6C, 0x6F])  # "Hello"
            send_binary_data(driver, peer_addr, binary_data)

            time.sleep(0.5)

            # Example 4: Send a file
            demo_file = Path("/tmp/demo_data.json")
            demo_file.write_text(
                json.dumps(
                    {
                        "source": "Python SDK",
                        "message": "This is a demo file transfer",
                        "data": [1, 2, 3, 4, 5],
                    },
                    indent=2,
                )
            )
            send_file(driver, peer_addr, demo_file)

            print("\n" + "=" * 60)
            print("✓ All Data Exchange examples completed")
            print("\nOn the target node, check:")
            print("  pilotctl inbox          # See text/JSON messages")
            print("  pilotctl received       # See transferred files")
            print("  ls ~/.pilot/inbox/")
            print("  ls ~/.pilot/received/")

    except PilotError as e:
        print(f"\n✗ Pilot error: {e}")
        print("\nHint: Start the daemon first:")
        print("  pilotctl daemon start --hostname sender-agent")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
