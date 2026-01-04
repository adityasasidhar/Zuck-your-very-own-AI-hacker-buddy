"""
Tool registry - Central place to manage all available tools.
"""

from typing import List, Optional, Any
import logging

logger = logging.getLogger('zuck_agent')

# Session memory storage (shared across tools)
_session_memory = {}


def get_session_memory():
    """Get the shared session memory."""
    return _session_memory


def clear_session_memory():
    """Clear the shared session memory."""
    global _session_memory
    _session_memory = {}


def get_all_tools() -> List[Any]:
    """
    Get list of all available tools.
    
    Returns:
        List of LangChain tool objects
    """
    from zuck.tools.calculator import calculator
    from zuck.tools.virustotal import virustotal_lookup
    from zuck.tools.datetime_tool import datetime_tool
    from zuck.tools.memory import memory_store
    from zuck.tools.file_reader import read_file
    from zuck.tools.http import http_request
    from zuck.tools.dns import dns_lookup
    from zuck.tools.whois import whois_lookup
    from zuck.tools.python_repl import get_python_repl_tool
    from zuck.tools.wikipedia import wikipedia_search
    
    tools = [
        calculator,
        virustotal_lookup,
        datetime_tool,
        memory_store,
        read_file,
        http_request,
        dns_lookup,
        whois_lookup,
        get_python_repl_tool(),
        wikipedia_search
    ]
    
    logger.info(f"Loaded {len(tools)} tools")
    return tools


def get_tool_by_name(name: str) -> Optional[Any]:
    """
    Get a specific tool by name.
    
    Args:
        name: Name of the tool to retrieve
        
    Returns:
        Tool object or None if not found
    """
    tools = get_all_tools()
    for tool in tools:
        if tool.name == name:
            return tool
    return None
