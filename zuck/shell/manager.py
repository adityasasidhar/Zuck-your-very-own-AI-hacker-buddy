"""
ShellManager - Manages multiple shell sessions.
"""

import uuid
import logging
from typing import Dict, Optional, List
from datetime import datetime

from zuck.shell.session import ShellSession

logger = logging.getLogger('zuck_agent')


class ShellManager:
    """
    Manages shell sessions for the agent.
    
    Provides:
    - A default persistent session
    - On-demand named sessions
    - Background process tracking
    """
    
    _instance: Optional['ShellManager'] = None
    
    def __new__(cls):
        """Singleton pattern - one manager per process."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.sessions: Dict[str, ShellSession] = {}
        self.default_session_id: Optional[str] = None
        self.background_processes: Dict[str, dict] = {}
        self._initialized = True
        
        # Create default session
        self._create_default_session()
        
        logger.info("ShellManager initialized")
    
    def _create_default_session(self):
        """Create the default persistent session."""
        session_id = "default"
        self.sessions[session_id] = ShellSession(session_id)
        self.default_session_id = session_id
        logger.info(f"Default shell session created: {session_id}")
    
    def get_default(self) -> ShellSession:
        """Get the default shell session."""
        if self.default_session_id is None or self.default_session_id not in self.sessions:
            self._create_default_session()
        
        session = self.sessions[self.default_session_id]
        
        # Restart if dead
        if not session.is_alive():
            logger.warning("Default session died, restarting...")
            self.sessions[self.default_session_id] = ShellSession(self.default_session_id)
            session = self.sessions[self.default_session_id]
        
        return session
    
    def create_session(self, name: Optional[str] = None) -> ShellSession:
        """
        Create a new named shell session.
        
        Args:
            name: Optional name for the session (auto-generated if not provided)
            
        Returns:
            New ShellSession instance
        """
        session_id = name or f"session_{uuid.uuid4().hex[:8]}"
        
        if session_id in self.sessions:
            logger.warning(f"Session {session_id} already exists, returning existing")
            return self.sessions[session_id]
        
        session = ShellSession(session_id)
        self.sessions[session_id] = session
        
        logger.info(f"Created new shell session: {session_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[ShellSession]:
        """Get a session by ID."""
        return self.sessions.get(session_id)
    
    def destroy_session(self, session_id: str) -> bool:
        """
        Destroy a shell session.
        
        Args:
            session_id: ID of session to destroy
            
        Returns:
            True if destroyed, False if not found
        """
        if session_id == self.default_session_id:
            logger.warning("Cannot destroy default session")
            return False
        
        if session_id in self.sessions:
            self.sessions[session_id].kill()
            del self.sessions[session_id]
            logger.info(f"Destroyed session: {session_id}")
            return True
        
        return False
    
    def list_sessions(self) -> List[dict]:
        """List all sessions with their status."""
        result = []
        for session_id, session in self.sessions.items():
            result.append({
                "id": session_id,
                "is_default": session_id == self.default_session_id,
                "is_alive": session.is_alive(),
                "created_at": session.created_at.isoformat(),
                "command_count": len(session.history)
            })
        return result
    
    def run_background(self, command: str, session_id: Optional[str] = None) -> str:
        """
        Run a command in the background.
        
        Args:
            command: Command to run
            session_id: Session to use (default if not specified)
            
        Returns:
            Process ID for tracking
        """
        session = self.get_session(session_id) if session_id else self.get_default()
        
        # Run with nohup and capture PID
        bg_id = uuid.uuid4().hex[:8]
        bg_command = f"nohup {command} > /tmp/zuck_bg_{bg_id}.out 2>&1 & echo $!"
        
        output = session.run_command(bg_command, timeout=5)
        pid = output.strip().split('\n')[-1]
        
        self.background_processes[bg_id] = {
            "pid": pid,
            "command": command,
            "started_at": datetime.now().isoformat(),
            "output_file": f"/tmp/zuck_bg_{bg_id}.out",
            "session_id": session.session_id
        }
        
        logger.info(f"Started background process {bg_id} (PID: {pid}): {command}")
        return bg_id
    
    def get_background_output(self, bg_id: str) -> str:
        """Get output from a background process."""
        if bg_id not in self.background_processes:
            return f"Unknown background process: {bg_id}"
        
        info = self.background_processes[bg_id]
        session = self.get_default()
        
        return session.run_command(f"cat {info['output_file']} 2>/dev/null || echo 'No output yet'")
    
    def kill_background(self, bg_id: str) -> bool:
        """Kill a background process."""
        if bg_id not in self.background_processes:
            return False
        
        info = self.background_processes[bg_id]
        session = self.get_default()
        
        session.run_command(f"kill {info['pid']} 2>/dev/null || true")
        del self.background_processes[bg_id]
        
        logger.info(f"Killed background process: {bg_id}")
        return True
    
    def list_background(self) -> List[dict]:
        """List all background processes."""
        result = []
        for bg_id, info in self.background_processes.items():
            # Check if still running
            session = self.get_default()
            is_running = session.run_command(f"ps -p {info['pid']} > /dev/null 2>&1 && echo running || echo stopped").strip() == "running"
            
            result.append({
                "id": bg_id,
                "pid": info["pid"],
                "command": info["command"],
                "started_at": info["started_at"],
                "is_running": is_running
            })
        return result
    
    def cleanup(self):
        """Clean up all sessions."""
        for session_id in list(self.sessions.keys()):
            self.sessions[session_id].kill()
        self.sessions.clear()
        self.background_processes.clear()
        self.default_session_id = None
        logger.info("ShellManager cleanup complete")
