"""
Shell execution tool with async support and command management.
"""

import os
import logging
import subprocess
import threading
import time
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# Allowed commands for security
ALLOWED_COMMANDS = {
    # Network tools
    'nmap', 'tcpdump', 'netcat', 'nc', 'curl', 'wget', 'ping', 'traceroute',
    'mtr', 'dig', 'nslookup', 'host', 'whois', 'ss', 'netstat', 'ip', 'ifconfig',
    
    # File/text tools
    'ls', 'cat', 'head', 'tail', 'grep', 'awk', 'sed', 'find', 'wc', 'sort',
    'uniq', 'cut', 'tr', 'diff', 'file', 'strings', 'xxd', 'hexdump',
    
    # System tools
    'ps', 'top', 'htop', 'free', 'df', 'du', 'uname', 'id', 'whoami', 'date',
    'uptime', 'env', 'printenv', 'which', 'whereis', 'lsof',
    
    # Security tools
    'nikto', 'sqlmap', 'gobuster', 'dirb', 'hydra', 'john', 'hashcat',
    'masscan', 'arp-scan', 'nbtscan', 'enum4linux', 'smbclient',
    
    # Others
    'echo', 'pwd', 'mkdir', 'touch', 'chmod', 'base64', 'md5sum', 'sha256sum',
    'python', 'python3', 'pip', 'git',
}

# Dangerous patterns to block
BLOCKED_PATTERNS = [
    'rm -rf /', 'rm -rf /*', 'mkfs', 'dd if=', '> /dev/',
    ':(){:|:&};:', 'chmod 777 /', 'wget | sh', 'curl | sh',
    '| bash', '| sh', 'sudo rm', 'sudo dd',
]


@dataclass
class CommandState:
    """State of a running/completed command."""
    command: str
    pid: int
    start_time: datetime
    status: str  # running, done, failed, terminated
    output: str = ""
    error: str = ""
    return_code: Optional[int] = None
    process: Optional[subprocess.Popen] = None


# Global command registry
_commands: Dict[str, CommandState] = {}
_command_counter = 0


def _generate_id() -> str:
    """Generate a unique command ID."""
    global _command_counter
    _command_counter += 1
    return f"cmd_{_command_counter}"


def _is_allowed(command: str) -> bool:
    """Check if command is allowed."""
    # Check for blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in command.lower():
            return False
    
    # Extract base command
    parts = command.strip().split()
    if not parts:
        return False
    
    base_cmd = parts[0].split('/')[-1]  # Handle full paths
    
    # Check against allowed list
    return base_cmd in ALLOWED_COMMANDS


def _run_async(cmd_id: str, command: str, timeout: int):
    """Run command in background thread."""
    state = _commands[cmd_id]
    
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, 'PAGER': 'cat'}
        )
        state.process = process
        state.pid = process.pid
        
        # Wait with timeout
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            state.output = stdout
            state.error = stderr
            state.return_code = process.returncode
            state.status = "done" if process.returncode == 0 else "failed"
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            state.output = stdout + "\n[TIMEOUT - command killed]"
            state.error = stderr
            state.status = "timeout"
            
    except Exception as e:
        state.error = str(e)
        state.status = "failed"


@tool
def shell_run(command: str, timeout: int = 30) -> str:
    """
    Execute a shell command and return output.
    
    Args:
        command: Shell command to execute
        timeout: Timeout in seconds (default: 30)
        
    Returns:
        Command output or error message
    """
    if not _is_allowed(command):
        return f"❌ Command not allowed: {command.split()[0]}"
    
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, 'PAGER': 'cat'}
        )
        
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]: {result.stderr}"
        if result.returncode != 0:
            output += f"\n[exit code: {result.returncode}]"
            
        return output if output else "[no output]"
        
    except subprocess.TimeoutExpired:
        return f"❌ Command timed out after {timeout}s"
    except Exception as e:
        return f"❌ Error: {e}"


@tool
def shell_run_background(command: str, timeout: int = 300) -> str:
    """
    Start a long-running command in the background.
    Returns a command ID to check status later.
    
    Args:
        command: Shell command to execute
        timeout: Max runtime in seconds (default: 300 = 5 min)
        
    Returns:
        Command ID for tracking
    """
    if not _is_allowed(command):
        return f"❌ Command not allowed: {command.split()[0]}"
    
    cmd_id = _generate_id()
    state = CommandState(
        command=command,
        pid=0,
        start_time=datetime.now(),
        status="running"
    )
    _commands[cmd_id] = state
    
    # Start in background thread
    thread = threading.Thread(target=_run_async, args=(cmd_id, command, timeout))
    thread.daemon = True
    thread.start()
    
    return f"🔄 Started: {cmd_id}\nCommand: {command}\nCheck status with shell_status('{cmd_id}')"


@tool
def shell_status(command_id: str) -> str:
    """
    Check status of a background command.
    
    Args:
        command_id: ID from shell_run_background
        
    Returns:
        Status and output of the command
    """
    if command_id not in _commands:
        return f"❌ Unknown command ID: {command_id}"
    
    state = _commands[command_id]
    
    result = f"Command: {state.command}\n"
    result += f"Status: {state.status}\n"
    result += f"Started: {state.start_time.strftime('%H:%M:%S')}\n"
    
    if state.status == "running":
        elapsed = (datetime.now() - state.start_time).seconds
        result += f"Running for: {elapsed}s\n"
    else:
        result += f"Exit code: {state.return_code}\n"
        if state.output:
            result += f"\n--- Output ---\n{state.output[:2000]}"
            if len(state.output) > 2000:
                result += "\n[truncated...]"
        if state.error:
            result += f"\n--- Errors ---\n{state.error[:500]}"
    
    return result


@tool
def shell_terminate(command_id: str) -> str:
    """
    Terminate a running background command.
    
    Args:
        command_id: ID from shell_run_background
        
    Returns:
        Result of termination
    """
    if command_id not in _commands:
        return f"❌ Unknown command ID: {command_id}"
    
    state = _commands[command_id]
    
    if state.status != "running":
        return f"Command already {state.status}"
    
    if state.process:
        state.process.terminate()
        time.sleep(0.5)
        if state.process.poll() is None:
            state.process.kill()
        state.status = "terminated"
        return f"✓ Terminated {command_id}"
    
    return f"❌ Cannot terminate (no process handle)"


@tool  
def shell_list() -> str:
    """
    List all tracked commands and their status.
    
    Returns:
        List of commands with status
    """
    if not _commands:
        return "No commands tracked"
    
    lines = ["ID | Status | Command"]
    lines.append("-" * 50)
    for cmd_id, state in _commands.items():
        cmd_short = state.command[:30] + "..." if len(state.command) > 30 else state.command
        lines.append(f"{cmd_id} | {state.status} | {cmd_short}")
    
    return "\n".join(lines)
