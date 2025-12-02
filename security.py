import re
import logging
from datetime import datetime
from typing import Optional, Tuple
from models import CommandProposal, SecurityLevel, AgentAction
from config import AgentConfig

logger = logging.getLogger('zuck_agent')

class SecurityValidator:
    """Enhanced security validation"""

    CRITICAL_PATTERNS = [
        (r'\brm\s+(-[rf]+\s+)?/(?!tmp|var/tmp)', SecurityLevel.CRITICAL, "Recursive delete from root"),
        (r'\bmkfs\b', SecurityLevel.CRITICAL, "Filesystem creation"),
        (r'\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/', SecurityLevel.CRITICAL, "Disk wipe"),
        (r':\(\)\{.*\|\:.*\&\}\;', SecurityLevel.CRITICAL, "Fork bomb"),
        (r'\bformat\b.*\b(disk|drive|partition)', SecurityLevel.CRITICAL, "Format disk"),
    ]

    HIGH_RISK_PATTERNS = [
        (r'\bshutdown\b', SecurityLevel.HIGH, "System shutdown"),
        (r'\breboot\b', SecurityLevel.HIGH, "System reboot"),
        (r'\binit\s+[06]', SecurityLevel.HIGH, "System halt/reboot"),
        (r'\bkillall\b', SecurityLevel.HIGH, "Kill all processes"),
        (r'\biptables\s+-F', SecurityLevel.HIGH, "Flush firewall"),
        (r'\bufw\s+disable', SecurityLevel.HIGH, "Disable firewall"),
        (r'/dev/(sd[a-z]|nvme[0-9])', SecurityLevel.HIGH, "Direct device access"),
    ]

    MEDIUM_RISK_PATTERNS = [
        (r'\bchmod\s+(-R\s+)?777', SecurityLevel.MEDIUM, "Insecure permissions"),
        (r'\bchown\s+-R.*/', SecurityLevel.MEDIUM, "Recursive ownership change"),
        (r'\bpkill\s+-9', SecurityLevel.MEDIUM, "Force kill processes"),
    ]

    @classmethod
    def analyze_command(cls, command: str) -> Tuple[bool, SecurityLevel, Optional[str]]:
        command_lower = command.lower().strip()

        logger.debug(f"Analyzing command security: {command[:50]}...")

        for pattern, level, desc in cls.CRITICAL_PATTERNS:
            if re.search(pattern, command_lower):
                logger.critical(f"CRITICAL security issue detected: {desc}")
                return False, level, f"CRITICAL: {desc}"

        for pattern, level, desc in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, command_lower):
                logger.error(f"HIGH RISK command detected: {desc}")
                return False, level, f"HIGH RISK: {desc}"

        for pattern, level, desc in cls.MEDIUM_RISK_PATTERNS:
            if re.search(pattern, command_lower):
                logger.warning(f"Medium risk command: {desc}")

        if any(sep in command for sep in [';', '&&', '||']):
            parts = re.split(r'[;&|]+', command)
            for part in parts:
                is_safe, level, reason = cls.analyze_command(part.strip())
                if not is_safe:
                    return False, level, f"Unsafe in chain: {reason}"

        logger.debug("Command passed security checks")
        return True, SecurityLevel.SAFE, None


class CommandValidator:
    def __init__(self, config: AgentConfig):
        self.config = config
        logger.debug("CommandValidator initialized")

    def validate(self, proposal: CommandProposal) -> Tuple[bool, Optional[str], SecurityLevel]:
        start_time = datetime.now()

        if proposal.action != AgentAction.EXECUTE_COMMAND:
            return True, None, SecurityLevel.SAFE

        command = proposal.command

        logger.debug(f"Validating command: {command}")

        if not command or not command.strip():
            return False, "Empty command", SecurityLevel.SAFE

        if len(command) > self.config.max_command_length:
            logger.warning(f"Command exceeds max length: {len(command)} > {self.config.max_command_length}")
            return False, f"Command exceeds max length ({self.config.max_command_length})", SecurityLevel.SAFE

        is_safe, risk_level, reason = SecurityValidator.analyze_command(command)

        validation_time = (datetime.now() - start_time).total_seconds()
        logger.debug(f"Validation completed in {validation_time:.3f}s")

        if not is_safe:
            return False, f"Security check failed [{risk_level}]: {reason}", risk_level

        base_cmd = command.split()[0].split('/')[-1]
        if base_cmd == 'sudo' and len(command.split()) > 1:
            base_cmd = command.split()[1].split('/')[-1]

        if base_cmd not in self.config.allowed_tools:
            logger.warning(f"Command '{base_cmd}' not in allowed tools list")

        return True, None, risk_level
