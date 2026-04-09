"""
Tools for {{AGENT_NAME}}.

EDIT THIS FILE to add the tools your agent can call.

Each tool needs:
  1. A Python function that takes a dict of args and returns a JSON-serializable dict
  2. An entry in TOOL_DEFINITIONS (Gemini function-calling schema)
  3. An entry in TOOL_FUNCTIONS (name → function mapping)

The agent (gemini_agent.py) automatically calls these tools when Gemini decides to.
"""

import json
import os
import subprocess
from pathlib import Path


# ---------------------------------------------------------------------------
# Example tool — delete this and replace with your own
# ---------------------------------------------------------------------------

def example_tool(args: dict) -> dict:
    """
    Example tool: returns a greeting.
    Replace this with real logic.
    """
    name = args.get("name", "world")
    return {"message": f"Hello, {name}!"}


# ---------------------------------------------------------------------------
# Add your own tools below
# ---------------------------------------------------------------------------

# def my_tool(args: dict) -> dict:
#     """Do something useful."""
#     param = args.get("param", "")
#     # ... your logic here ...
#     return {"result": "..."}


# ---------------------------------------------------------------------------
# Tool definitions — describe each tool for Gemini
# ---------------------------------------------------------------------------
# See: https://ai.google.dev/api/generate-content#v1beta.Tool
#
# Supported parameter types: string, integer, number, boolean, array, object
# Use "enum" to restrict string values.
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS = [
    {
        "name": "example_tool",
        "description": "An example tool that returns a greeting. Delete this and add your real tools.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name to greet",
                },
            },
            "required": [],
        },
    },
    # Add more tool definitions here:
    # {
    #     "name": "my_tool",
    #     "description": "What this tool does and when to use it",
    #     "parameters": {
    #         "type": "object",
    #         "properties": {
    #             "param": {
    #                 "type": "string",
    #                 "description": "What this parameter is for",
    #             },
    #         },
    #         "required": ["param"],
    #     },
    # },
]

# Map tool names to their Python functions
TOOL_FUNCTIONS = {
    "example_tool": example_tool,
    # "my_tool": my_tool,
}
