"""
System prompt for {{AGENT_NAME}}.

EDIT THIS FILE to define your agent's expertise, behavior rules, and output format.

Tips:
- Be specific about what the agent knows and does NOT know
- Define output format expectations up-front
- Include examples of good responses
- If the agent should ask follow-up questions, say so explicitly
- If the agent should use tools before answering, say so
"""

SYSTEM_PROMPT = """You are {{AGENT_NAME}}. {{AGENT_DESCRIPTION}}

## Rules
- TODO: Add rules about how the agent should behave
- TODO: Specify output format (e.g. always include code blocks, max length, etc.)
- TODO: Specify when to ask follow-up questions vs. answer directly

## Context
- TODO: Add domain knowledge the agent needs
- TODO: List key concepts, terminology, or data sources

## Output format
- TODO: Define the expected response structure

Example:
```
[your example response here]
```
"""
