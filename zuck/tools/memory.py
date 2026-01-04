"""
Session memory storage tool.
"""

import logging

from langchain.tools import tool
from zuck.tools.registry import get_session_memory

logger = logging.getLogger('zuck_agent')


@tool
def memory_store(action: str, key: str = None, value: str = None) -> str:
    """
    Store and retrieve findings during the session for context building.
    
    Args:
        action: Action to perform - 'store', 'retrieve', 'list', 'clear'
        key: Key for storage/retrieval
        value: Value to store (for 'store' action)
        
    Returns:
        Result of the memory operation
        
    Examples:
        memory_store("store", "scan_result", "Found 5 open ports")
        memory_store("retrieve", "scan_result")
        memory_store("list")
    """
    memory = get_session_memory()
    
    try:
        if action == "store":
            if not key or value is None:
                return "Error: Both key and value required for store action"
            memory[key] = value
            return f"Stored: {key} = {value[:100]}..." if len(value) > 100 else f"Stored: {key} = {value}"
        
        elif action == "retrieve":
            if not key:
                return "Error: Key required for retrieve action"
            if key in memory:
                return f"{key}: {memory[key]}"
            else:
                return f"Key '{key}' not found in memory"
        
        elif action == "list":
            if not memory:
                return "Memory is empty"
            keys = list(memory.keys())
            return f"Stored keys ({len(keys)}): {', '.join(keys)}"
        
        elif action == "clear":
            count = len(memory)
            memory.clear()
            return f"Cleared {count} items from memory"
        
        else:
            return f"Error: Unknown action '{action}'. Use: store, retrieve, list, clear"
            
    except Exception as e:
        logger.error(f"Memory tool error: {e}")
        return f"Error: {str(e)}"
