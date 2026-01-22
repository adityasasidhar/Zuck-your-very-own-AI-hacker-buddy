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
    tools = []
    
    # === Shell Tools (primary interface) ===
    from zuck.shell.tools import (
        shell_run, shell_run_background, shell_send_input,
        shell_read_output, shell_get_cwd, shell_interrupt,
        shell_list_processes, shell_get_background_output,
        shell_kill_background, shell_create_session,
        shell_switch_session, shell_list_sessions,
        shell_destroy_session, shell_get_history
    )
    tools.extend([
        shell_run, shell_run_background, shell_send_input,
        shell_read_output, shell_get_cwd, shell_interrupt,
        shell_list_processes, shell_get_background_output,
        shell_kill_background, shell_create_session,
        shell_switch_session, shell_list_sessions,
        shell_destroy_session, shell_get_history
    ])
    
    # === Original Tools ===
    from zuck.tools.virustotal import virustotal_lookup
    from zuck.tools.http import http_request
    from zuck.tools.python_repl import get_python_repl_tool
    from zuck.tools.wikipedia import wikipedia_search
    
    tools.extend([
        virustotal_lookup, http_request,
        get_python_repl_tool(), wikipedia_search
    ])
    
    # === OSINT Tools ===
    from zuck.tools.shodan import shodan_host_lookup, shodan_search
    from zuck.tools.social_analyzer import username_search, email_osint
    
    tools.extend([
        shodan_host_lookup, shodan_search,
        username_search, email_osint
    ])
    
    # === Offensive Tools ===
    from zuck.tools.exploit_db import cve_lookup, search_exploits, exploit_info
    from zuck.tools.sql_injection import sqli_payloads
    
    tools.extend([
        cve_lookup, search_exploits, exploit_info,
        sqli_payloads
    ])
    
    # === Utility Tools ===
    from zuck.tools.timer import wait_timer
    tools.extend([wait_timer])
    
    # === Planning Tools ===
    from zuck.tools.planner import create_plan, update_plan_step, get_current_plan
    tools.extend([create_plan, update_plan_step, get_current_plan])
    
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


def list_tools() -> List[str]:
    """Get list of all tool names."""
    return [tool.name for tool in get_all_tools()]
