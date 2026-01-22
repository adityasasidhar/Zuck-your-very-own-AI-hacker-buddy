"""
Shell tools - LangChain tools for agent shell access.
"""

import json
import logging
from typing import Optional

from langchain.tools import tool

from zuck.shell.manager import ShellManager

logger = logging.getLogger('zuck_agent')

# Singleton manager instance
_manager: Optional[ShellManager] = None


def get_manager() -> ShellManager:
    """Get or create the shell manager."""
    global _manager
    if _manager is None:
        _manager = ShellManager()
    return _manager


@tool
def shell_run(command: str, timeout: float = 5.0) -> str:
    """
    Run a shell command and return the output.
    
    The shell maintains persistent state - working directory, environment
    variables, and aliases persist between commands.
    
    Args:
        command: Shell command to execute (e.g., "ls -la", "cd /tmp && pwd")
        timeout: Maximum seconds to wait for output (default: 5)
        
    Returns:
        Command output as string
        
    Examples:
        shell_run("ls -la")
        shell_run("cd /tmp && touch test.txt")
        shell_run("grep -r 'pattern' .")
    """
    manager = get_manager()
    session = manager.get_default()
    
    logger.info(f"shell_run: {command}")
    output = session.run_command(command, timeout=timeout)
    
    return output


@tool
def shell_run_background(command: str) -> str:
    """
    Run a command in the background.
    
    Returns a process ID that can be used to check output or kill the process.
    
    Args:
        command: Command to run in background
        
    Returns:
        JSON with process ID for tracking
        
    Examples:
        shell_run_background("python3 server.py")
        shell_run_background("nmap -sV target.com")
    """
    manager = get_manager()
    bg_id = manager.run_background(command)
    
    return json.dumps({
        "status": "started",
        "bg_id": bg_id,
        "message": f"Process started. Use shell_get_background_output('{bg_id}') to check output."
    })


@tool
def shell_send_input(text: str) -> str:
    """
    Send input to the shell (for interactive commands).
    
    Use this for:
    - Responding to prompts (y/n)
    - Sending input to REPLs (python, node)
    - Sending special keys (use \\n for Enter, \\x03 for Ctrl+C)
    
    Args:
        text: Input to send (include \\n for Enter key)
        
    Returns:
        Confirmation message
        
    Examples:
        shell_send_input("y\\n")  # Answer "yes" to a prompt
        shell_send_input("print('hello')\\n")  # Send to Python REPL
        shell_send_input("\\x03")  # Send Ctrl+C to interrupt
    """
    manager = get_manager()
    session = manager.get_default()
    
    # Handle escape sequences
    text = text.encode().decode('unicode_escape')
    
    session.send_input(text)
    logger.info(f"shell_send_input: {repr(text)}")
    
    return f"Sent input: {repr(text)}"


@tool
def shell_read_output(timeout: float = 2.0) -> str:
    """
    Read available output from the shell.
    
    Use after shell_send_input to see the result, or to check
    output from long-running commands.
    
    Args:
        timeout: Maximum seconds to wait for output (default: 2)
        
    Returns:
        Available output from the shell
    """
    manager = get_manager()
    session = manager.get_default()
    
    output = session.read_output(timeout=timeout)
    return output if output else "(no output available)"


@tool
def shell_get_cwd() -> str:
    """
    Get the current working directory of the shell.
    
    Returns:
        Current directory path
    """
    manager = get_manager()
    session = manager.get_default()
    return session.get_cwd()


@tool
def shell_interrupt() -> str:
    """
    Send Ctrl+C to interrupt the current command.
    
    Use this to stop long-running or hung commands.
    
    Returns:
        Confirmation message
    """
    manager = get_manager()
    session = manager.get_default()
    session.interrupt()
    return "Sent interrupt signal (Ctrl+C)"


@tool
def shell_list_processes() -> str:
    """
    List all background processes started by the agent.
    
    Returns:
        JSON list of background processes with status
    """
    manager = get_manager()
    processes = manager.list_background()
    return json.dumps(processes, indent=2)


@tool  
def shell_get_background_output(bg_id: str) -> str:
    """
    Get output from a background process.
    
    Args:
        bg_id: Background process ID from shell_run_background
        
    Returns:
        Output from the background process
    """
    manager = get_manager()
    return manager.get_background_output(bg_id)


@tool
def shell_kill_background(bg_id: str) -> str:
    """
    Kill a background process.
    
    Args:
        bg_id: Background process ID to kill
        
    Returns:
        Confirmation message
    """
    manager = get_manager()
    if manager.kill_background(bg_id):
        return f"Killed background process: {bg_id}"
    return f"Background process not found: {bg_id}"


@tool
def shell_create_session(name: str) -> str:
    """
    Create a new named shell session.
    
    Each session has its own working directory and state.
    
    Args:
        name: Name for the new session
        
    Returns:
        Confirmation with session ID
    """
    manager = get_manager()
    session = manager.create_session(name)
    return json.dumps({
        "status": "created",
        "session_id": session.session_id,
        "message": f"Session '{name}' created. Use shell_switch_session('{name}') to use it."
    })


@tool
def shell_switch_session(session_id: str) -> str:
    """
    Switch to a different shell session.
    
    Note: This affects all subsequent shell_run commands.
    
    Args:
        session_id: Session ID to switch to (or "default" for main session)
        
    Returns:
        Confirmation message
    """
    manager = get_manager()
    session = manager.get_session(session_id)
    
    if session is None:
        return f"Session not found: {session_id}"
    
    manager.default_session_id = session_id
    return f"Switched to session: {session_id}"


@tool
def shell_list_sessions() -> str:
    """
    List all shell sessions.
    
    Returns:
        JSON list of sessions with status
    """
    manager = get_manager()
    sessions = manager.list_sessions()
    return json.dumps(sessions, indent=2)


@tool
def shell_destroy_session(session_id: str) -> str:
    """
    Destroy a shell session.
    
    Cannot destroy the default session.
    
    Args:
        session_id: Session ID to destroy
        
    Returns:
        Confirmation message
    """
    manager = get_manager()
    if manager.destroy_session(session_id):
        return f"Destroyed session: {session_id}"
    return f"Could not destroy session: {session_id} (may be default or not found)"


@tool
def shell_get_history(limit: int = 20) -> str:
    """
    Get recent command history from the current shell session.
    
    Args:
        limit: Maximum number of commands to return (default: 20)
        
    Returns:
        JSON list of recent commands and their outputs
    """
    manager = get_manager()
    session = manager.get_default()
    history = session.get_history()[-limit:]
    return json.dumps(history, indent=2)
