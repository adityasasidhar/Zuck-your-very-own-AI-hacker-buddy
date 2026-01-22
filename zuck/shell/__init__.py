"""
Shell module - Interactive PTY-based shell for the Zuck agent.
"""

from zuck.shell.manager import ShellManager
from zuck.shell.session import ShellSession

__all__ = ["ShellSession", "ShellManager"]
