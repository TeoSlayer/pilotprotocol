"""Command-line interface wrappers for Pilot Protocol binaries.

This module provides entry points for the bundled Go binaries:
- pilotctl: CLI tool for managing the daemon
- pilot-daemon: Background service
- pilot-gateway: IP traffic bridge

Each wrapper:
1. Ensures ~/.pilot/ directory exists
2. Creates default config.json if missing
3. Executes the bundled binary with all arguments passed through
"""

import json
import os
import subprocess
import sys
from pathlib import Path


def _ensure_pilot_env():
    """Ensure ~/.pilot/ directory and config.json exist.
    
    Creates:
    - ~/.pilot/ directory
    - ~/.pilot/config.json with default settings (if not present)
    
    This function is called before every binary execution to ensure
    the runtime environment is properly initialized.
    """
    # Get user's home directory
    home = Path.home()
    pilot_dir = home / ".pilot"
    config_file = pilot_dir / "config.json"
    
    # Create ~/.pilot/ if it doesn't exist
    pilot_dir.mkdir(parents=True, exist_ok=True)
    
    # Create default config.json if it doesn't exist
    if not config_file.exists():
        default_config = {
            "registry": "34.71.57.205:9000",
            "beacon": "34.71.57.205:9001",
            "socket": "/tmp/pilot.sock",
            "encrypt": True,
            "identity": str(pilot_dir / "identity.json")
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)


def _get_binary_path(binary_name: str) -> Path:
    """Get absolute path to a bundled binary.
    
    Args:
        binary_name: Name of the binary (e.g., 'pilotctl', 'pilot-daemon')
        
    Returns:
        Absolute path to the binary
        
    Raises:
        FileNotFoundError: If binary not found in package
    """
    # Find the bin/ directory relative to this file
    package_dir = Path(__file__).resolve().parent
    bin_dir = package_dir / "bin"
    binary_path = bin_dir / binary_name
    
    if not binary_path.exists():
        raise FileNotFoundError(
            f"Binary '{binary_name}' not found at {binary_path}\n"
            f"Expected location: {bin_dir}\n"
            "The wheel may not have been built correctly."
        )
    
    return binary_path


def run_pilotctl():
    """Entry point for pilotctl CLI tool.
    
    This is called when the user runs 'pilotctl' from the command line.
    All arguments are passed through to the Go binary.
    
    Example:
        $ pilotctl daemon start --hostname my-agent
        $ pilotctl info
        $ pilotctl ping other-agent
    """
    # Ensure environment is set up
    _ensure_pilot_env()
    
    # Get path to bundled binary
    binary = _get_binary_path("pilotctl")
    
    # Execute the binary with all arguments
    # subprocess.call() returns the exit code directly
    exit_code = subprocess.call([str(binary)] + sys.argv[1:])
    
    # Exit with the same code as the binary
    sys.exit(exit_code)


def run_daemon():
    """Entry point for pilot-daemon background service.
    
    This is called when the user runs 'pilot-daemon' from the command line.
    All arguments are passed through to the Go binary.
    
    Example:
        $ pilot-daemon -registry 34.71.57.205:9000 -beacon 34.71.57.205:9001
        $ pilot-daemon -hostname my-agent -public
    """
    # Ensure environment is set up
    _ensure_pilot_env()
    
    # Get path to bundled binary
    binary = _get_binary_path("pilot-daemon")
    
    # Execute the binary with all arguments
    exit_code = subprocess.call([str(binary)] + sys.argv[1:])
    
    # Exit with the same code as the binary
    sys.exit(exit_code)


def run_gateway():
    """Entry point for pilot-gateway IP traffic bridge.
    
    This is called when the user runs 'pilot-gateway' from the command line.
    All arguments are passed through to the Go binary.
    
    Example:
        $ pilot-gateway --ports 80,3000 <pilot-addr>
    """
    # Ensure environment is set up
    _ensure_pilot_env()
    
    # Get path to bundled binary
    binary = _get_binary_path("pilot-gateway")
    
    # Execute the binary with all arguments
    exit_code = subprocess.call([str(binary)] + sys.argv[1:])
    
    # Exit with the same code as the binary
    sys.exit(exit_code)
