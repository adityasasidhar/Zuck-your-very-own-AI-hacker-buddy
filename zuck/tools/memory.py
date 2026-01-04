"""
Session memory storage tool.
"""

import json
import logging
from typing import Optional

from langchain.tools import tool
from zuck.tools.registry import get_session_memory

logger = logging.getLogger('zuck_agent')


@tool
def memory_store(action: str, key: str = "", value: str = "") -> str:
    """
    Store and retrieve findings during the session.
    
    Args:
        action: Action - 'store', 'retrieve', 'list', or 'clear'
        key: Key for storage/retrieval (required for store/retrieve)
        value: Value to store (required for store, must be string)
        
    Returns:
        Result of the operation
    """
    memory = get_session_memory()
    
    try:
        if action == "store":
            if not key or not value:
                return "Error: Both key and value required for store"
            # Convert to string if needed
            if not isinstance(value, str):
                value = json.dumps(value)
            memory[key] = value
            display = value[:100] + "..." if len(value) > 100 else value
            return f"Stored: {key} = {display}"
        
        elif action == "retrieve":
            if not key:
                return "Error: Key required for retrieve"
            if key in memory:
                return f"{key}: {memory[key]}"
            return f"Key '{key}' not found"
        
        elif action == "list":
            if not memory:
                return "Memory is empty"
            return f"Keys ({len(memory)}): {', '.join(memory.keys())}"
        
        elif action == "clear":
            count = len(memory)
            memory.clear()
            return f"Cleared {count} items"
        
        else:
            return f"Unknown action: {action}"
            
    except Exception as e:
        return f"Error: {e}"
