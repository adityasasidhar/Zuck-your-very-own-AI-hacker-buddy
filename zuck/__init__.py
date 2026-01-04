"""
Zuck - AI Cybersecurity Agent for Linux Systems

A modular AI-powered cybersecurity assistant that can execute commands,
use security tools, and help with system analysis.
"""

__version__ = "1.0.0"
__author__ = "Aditya Sasidhar"

from zuck.core.agent import ZuckAgent
from zuck.core.config import AgentConfig
from zuck.core.models import (
    CommandProposal,
    CommandResult,
    CommandStatus,
    AgentAction,
    SecurityLevel,
)

__all__ = [
    "ZuckAgent",
    "AgentConfig",
    "CommandProposal",
    "CommandResult",
    "CommandStatus",
    "AgentAction",
    "SecurityLevel",
    "__version__",
]
