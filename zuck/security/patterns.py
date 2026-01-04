"""
Security patterns for command validation.
"""

from zuck.core.models import SecurityLevel

# Critical patterns - commands that should NEVER be executed
CRITICAL_PATTERNS = [
    (r'\brm\s+(-[rf]+\s+)?/(?!tmp|var/tmp)', SecurityLevel.CRITICAL, "Recursive delete from root"),
    (r'\bmkfs\b', SecurityLevel.CRITICAL, "Filesystem creation"),
    (r'\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/', SecurityLevel.CRITICAL, "Disk wipe"),
    (r':\(\)\{.*\|\:.*\&\}\;', SecurityLevel.CRITICAL, "Fork bomb"),
    (r'\bformat\b.*\b(disk|drive|partition)', SecurityLevel.CRITICAL, "Format disk"),
]

# High risk patterns - require extra confirmation
HIGH_RISK_PATTERNS = [
    (r'\bshutdown\b', SecurityLevel.HIGH, "System shutdown"),
    (r'\breboot\b', SecurityLevel.HIGH, "System reboot"),
    (r'\binit\s+[06]', SecurityLevel.HIGH, "System halt/reboot"),
    (r'\bkillall\b', SecurityLevel.HIGH, "Kill all processes"),
    (r'\biptables\s+-F', SecurityLevel.HIGH, "Flush firewall"),
    (r'\bufw\s+disable', SecurityLevel.HIGH, "Disable firewall"),
    (r'/dev/(sd[a-z]|nvme[0-9])', SecurityLevel.HIGH, "Direct device access"),
]

# Medium risk patterns - show warning
MEDIUM_RISK_PATTERNS = [
    (r'\bchmod\s+(-R\s+)?777', SecurityLevel.MEDIUM, "Insecure permissions"),
    (r'\bchown\s+-R.*/', SecurityLevel.MEDIUM, "Recursive ownership change"),
    (r'\bpkill\s+-9', SecurityLevel.MEDIUM, "Force kill processes"),
]
