"""Pilot Protocol Python SDK — ctypes FFI to the Go driver.

The Go ``pkg/driver`` package is the single source of truth.  This SDK
calls into the compiled C-shared library (``libpilot.so`` / ``.dylib`` /
``.dll``) via :mod:`ctypes`, giving Python the same capabilities with
zero protocol reimplementation.
"""

from .client import Conn, Driver, Listener, PilotError, DEFAULT_SOCKET_PATH

__all__ = [
    "Conn",
    "Driver",
    "Listener",
    "PilotError",
    "DEFAULT_SOCKET_PATH",
]
