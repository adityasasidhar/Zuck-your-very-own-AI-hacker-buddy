"""
Command validation for security.
"""

import logging
from datetime import datetime
from typing import Optional, Tuple

from zuck.core.config import AgentConfig
from zuck.core.models import CommandProposal, SecurityLevel, AgentAction

logger = logging.getLogger('zuck_agent')


class SecurityValidator:
    """Security validation for commands (logging only - no blocking)."""

    @classmethod
    def analyze_command(cls, command: str) -> Tuple[bool, SecurityLevel, Optional[str]]:
        """
        Analyze a command for security risks (logging only).
        
        Note: Guardrails disabled - all commands are allowed.
        
        Args:
            command: The command string to analyze
            
        Returns:
            Tuple of (is_safe, risk_level, reason) - always returns True
        """
        command_lower = command.lower().strip()
        logger.debug(f"Command (no guardrails): {command}")
        return True, SecurityLevel.SAFE, None


class CommandValidator:
    """Validates commands before execution."""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        logger.debug("CommandValidator initialized")

    def validate(self, proposal: CommandProposal) -> Tuple[bool, Optional[str], SecurityLevel]:
        """
        Validate a command proposal.
        
        Args:
            proposal: The command proposal to validate
            
        Returns:
            Tuple of (is_valid, error_message, risk_level)
        """
        start_time = datetime.now()

        if proposal.action != AgentAction.EXECUTE_COMMAND:
            return True, None, SecurityLevel.SAFE

        command = proposal.command

        logger.debug(f"Validating command: {command}")

        # Check for empty command
        if not command or not command.strip():
            return False, "Empty command", SecurityLevel.SAFE

        # Check command length
        if len(command) > self.config.max_command_length:
            logger.warning(f"Command exceeds max length: {len(command)} > {self.config.max_command_length}")
            return False, f"Command exceeds max length ({self.config.max_command_length})", SecurityLevel.SAFE

        # Security analysis
        is_safe, risk_level, reason = SecurityValidator.analyze_command(command)

        validation_time = (datetime.now() - start_time).total_seconds()
        logger.debug(f"Validation completed in {validation_time:.3f}s")

        if not is_safe:
            return False, f"Security check failed [{risk_level}]: {reason}", risk_level

        # Check if base command is in allowed tools
        base_cmd = command.split()[0].split('/')[-1]
        if base_cmd == 'sudo' and len(command.split()) > 1:
            base_cmd = command.split()[1].split('/')[-1]

        if base_cmd not in self.config.allowed_tools:
            logger.warning(f"Command '{base_cmd}' not in allowed tools list")

        return True, None, risk_level
