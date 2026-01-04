"""
Log analysis tool for security monitoring.
"""

import json
import logging
import re
from pathlib import Path
from collections import Counter
from datetime import datetime
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# Common attack patterns
ATTACK_PATTERNS = {
    "sql_injection": [r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r"--\s*$"],
    "xss": [r"<script", r"javascript:", r"onerror\s*=", r"onload\s*="],
    "path_traversal": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow"],
    "command_injection": [r";\s*\w+", r"\|\s*\w+", r"`.*`", r"\$\(.*\)"],
    "brute_force": [r"Failed password", r"authentication failure", r"Invalid user"],
}

@tool
def analyze_auth_log(filepath: str = "/var/log/auth.log", lines: int = 500) -> str:
    """
    Analyze authentication logs for security events.
    
    Args:
        filepath: Path to auth log
        lines: Number of lines to analyze
        
    Returns:
        Analysis of authentication events
    """
    try:
        path = Path(filepath).expanduser()
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        with open(path, 'r', errors='ignore') as f:
            log_lines = f.readlines()[-lines:]
        
        failed_logins = []
        successful_logins = []
        sudo_commands = []
        ssh_connections = []
        
        failed_pattern = re.compile(r"Failed password for (\w+) from ([\d.]+)")
        success_pattern = re.compile(r"Accepted \w+ for (\w+) from ([\d.]+)")
        sudo_pattern = re.compile(r"sudo:.*COMMAND=(.*)")
        
        for line in log_lines:
            if match := failed_pattern.search(line):
                failed_logins.append({"user": match.group(1), "ip": match.group(2)})
            elif match := success_pattern.search(line):
                successful_logins.append({"user": match.group(1), "ip": match.group(2)})
            elif match := sudo_pattern.search(line):
                sudo_commands.append(match.group(1)[:100])
        
        # Count failed attempts by IP
        failed_ips = Counter(f["ip"] for f in failed_logins)
        
        result = {
            "file": filepath,
            "lines_analyzed": len(log_lines),
            "summary": {
                "failed_logins": len(failed_logins),
                "successful_logins": len(successful_logins),
                "sudo_commands": len(sudo_commands)
            },
            "top_failed_ips": dict(failed_ips.most_common(10)),
            "potential_brute_force": [ip for ip, count in failed_ips.items() if count > 5],
            "recent_sudo": sudo_commands[-5:]
        }
        
        return json.dumps(result, indent=2)
        
    except PermissionError:
        return f"Error: Permission denied. Try: sudo cat {filepath}"
    except Exception as e:
        return f"Error: {e}"


@tool
def analyze_web_log(filepath: str, lines: int = 500) -> str:
    """
    Analyze web server logs for attacks.
    
    Args:
        filepath: Path to access log
        lines: Lines to analyze
        
    Returns:
        Attack detection results
    """
    try:
        path = Path(filepath).expanduser()
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        with open(path, 'r', errors='ignore') as f:
            log_lines = f.readlines()[-lines:]
        
        attacks = {pattern: [] for pattern in ATTACK_PATTERNS}
        status_codes = Counter()
        ips = Counter()
        
        # Apache/Nginx log pattern
        log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"[A-Z]+ ([^"]+)" (\d+)')
        
        for line in log_lines:
            if match := log_pattern.search(line):
                ip, request, status = match.groups()
                ips[ip] += 1
                status_codes[status] += 1
                
                for attack_type, patterns in ATTACK_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, request, re.IGNORECASE):
                            attacks[attack_type].append({"ip": ip, "request": request[:100]})
                            break
        
        result = {
            "file": filepath,
            "lines_analyzed": len(log_lines),
            "status_codes": dict(status_codes.most_common(10)),
            "top_ips": dict(ips.most_common(10)),
            "attacks_detected": {k: len(v) for k, v in attacks.items() if v},
            "attack_samples": {k: v[:3] for k, v in attacks.items() if v}
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return f"Error: {e}"


@tool
def search_logs(pattern: str, log_path: str = "/var/log", file_pattern: str = "*.log") -> str:
    """
    Search logs for specific patterns.
    
    Args:
        pattern: Regex pattern to search
        log_path: Directory to search
        file_pattern: File glob pattern
        
    Returns:
        Matching log entries
    """
    try:
        path = Path(log_path)
        matches = []
        
        for log_file in path.glob(file_pattern):
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    for i, line in enumerate(f.readlines()[-200:]):
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append({
                                "file": str(log_file),
                                "line": line.strip()[:200]
                            })
                            if len(matches) >= 50:
                                break
            except PermissionError:
                continue
        
        return json.dumps({
            "pattern": pattern,
            "matches_found": len(matches),
            "matches": matches[:20]
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"
