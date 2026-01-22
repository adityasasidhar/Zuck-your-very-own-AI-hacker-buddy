"""
LLM module - Provider abstraction for multiple LLM backends.
"""

from zuck.llm.factory import create_provider

__all__ = [
    "create_provider",
]
