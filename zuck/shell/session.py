"""
ShellSession - PTY-based interactive shell session.
"""

import logging
import os
import pty
import select
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger('zuck_agent')


@dataclass
class CommandRecord:
    """Record of a command execution."""
    command: str
    output: str
    timestamp: datetime = field(default_factory=datetime.now)
    exit_code: Optional[int] = None
    duration: float = 0.0


class ShellSession:
    """
    Interactive PTY-based shell session.
    
    Provides a persistent shell with:
    - Real terminal emulation via PTY
    - Persistent working directory and environment
    - Interactive command support (REPLs, prompts)
    - Non-blocking output reading
    """
    
    def __init__(self, session_id: str, shell: str = "/bin/bash"):
        self.session_id = session_id
        self.shell = shell
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None
        self.process: Optional[subprocess.Popen] = None
        self.history: List[CommandRecord] = []
        self.created_at = datetime.now()
        self._buffer = ""
        
        self._start_shell()
    
    def _start_shell(self):
        """Start the PTY shell process."""
        # Create pseudo-terminal
        self.master_fd, self.slave_fd = pty.openpty()
        
        # Start shell process
        self.process = subprocess.Popen(
            [self.shell, "-i"],  # Interactive shell
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            preexec_fn=os.setsid,  # New session
            env={
                **os.environ,
                "TERM": "xterm-256color",
                "PS1": "$ ",  # Simple prompt for easier parsing
            }
        )
        
        # Close slave in parent (only needed in child)
        os.close(self.slave_fd)
        self.slave_fd = None
        
        # Wait for shell to initialize and clear initial output
        time.sleep(0.1)
        self._read_available(timeout=0.5)
        
        logger.info(f"Shell session {self.session_id} started (PID: {self.process.pid})")
    
    def _read_available(self, timeout: float = 0.5) -> str:
        """Read all available output from the shell (non-blocking)."""
        if self.master_fd is None:
            return ""
        
        output = ""
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            ready, _, _ = select.select([self.master_fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(self.master_fd, 4096).decode('utf-8', errors='replace')
                    if chunk:
                        output += chunk
                    else:
                        break
                except OSError:
                    break
            elif output:
                # Got some output and no more available
                break
        
        return output
    
    def run_command(self, command: str, timeout: float = 5.0) -> str:
        """
        Run a command and return its output.
        
        Args:
            command: Command to execute
            timeout: Maximum time to wait for output (default: 5 seconds)
            
        Returns:
            Command output as string
        """
        if not self.is_alive():
            return "Error: Shell session is not running"
        
        start_time = time.time()
        
        # Clear any pending output
        self._read_available(timeout=0.1)
        
        # Send command with newline
        self._write(command + "\n")
        
        # Wait a bit for command to start
        time.sleep(0.1)
        
        # Read output until we see the prompt or timeout
        output = ""
        while time.time() - start_time < timeout:
            chunk = self._read_available(timeout=0.5)
            if chunk:
                output += chunk
                # Check if we're back at prompt (command finished)
                if output.rstrip().endswith("$"):
                    break
            elif not self.is_alive():
                break
        
        duration = time.time() - start_time
        
        # Clean up output (remove command echo and prompt)
        lines = output.split('\n')
        # Remove first line (command echo) and last line (prompt)
        if len(lines) > 1:
            if lines[0].strip().endswith(command.strip()):
                lines = lines[1:]
            if lines and lines[-1].strip() in ['$', '']:
                lines = lines[:-1]
        
        clean_output = '\n'.join(lines).strip()
        
        # Record command
        self.history.append(CommandRecord(
            command=command,
            output=clean_output,
            duration=duration
        ))
        
        logger.debug(f"Command executed in {duration:.2f}s: {command}")
        
        return clean_output
    
    def _write(self, text: str):
        """Write text to the shell."""
        if self.master_fd is not None:
            os.write(self.master_fd, text.encode('utf-8'))
    
    def send_input(self, text: str):
        """
        Send raw input to the shell (for interactive commands).
        
        Args:
            text: Input to send (include newline if needed)
        """
        self._write(text)
        logger.debug(f"Sent input: {repr(text[:50])}")
    
    def read_output(self, timeout: float = 1.0) -> str:
        """
        Read available output from the shell.
        
        Args:
            timeout: Maximum time to wait for output
            
        Returns:
            Output string
        """
        return self._read_available(timeout=timeout)
    
    def send_signal(self, sig: int):
        """Send a signal to the shell process."""
        if self.process:
            os.killpg(os.getpgid(self.process.pid), sig)
    
    def interrupt(self):
        """Send Ctrl+C to the shell."""
        self.send_signal(signal.SIGINT)
    
    def is_alive(self) -> bool:
        """Check if the shell process is still running."""
        if self.process is None:
            return False
        return self.process.poll() is None
    
    def get_cwd(self) -> str:
        """Get the current working directory."""
        return self.run_command("pwd").strip()
    
    def get_env(self, var: str) -> str:
        """Get an environment variable value."""
        return self.run_command(f"echo ${var}").strip()
    
    def kill(self):
        """Kill the shell session."""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=2)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
        
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except Exception:
                pass
            self.master_fd = None
        
        logger.info(f"Shell session {self.session_id} killed")
    
    def get_history(self) -> List[Dict[str, Any]]:
        """Get command history."""
        return [
            {
                "command": r.command,
                "output": r.output[:200] + "..." if len(r.output) > 200 else r.output,
                "timestamp": r.timestamp.isoformat(),
                "duration": f"{r.duration:.2f}s"
            }
            for r in self.history
        ]
    
    def __del__(self):
        """Cleanup on destruction."""
        self.kill()
