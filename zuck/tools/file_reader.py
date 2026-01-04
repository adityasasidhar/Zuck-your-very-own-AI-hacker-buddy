"""
Safe file reader tool.
"""

import json
import logging
from pathlib import Path

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def read_file(filepath: str, max_lines: int = 100) -> str:
    """
    Read and analyze configuration files and logs safely.
    
    Args:
        filepath: Path to the file to read
        max_lines: Maximum number of lines to read (default: 100)
        
    Returns:
        File content with metadata
        
    Examples:
        read_file("/etc/hosts")
        read_file("/var/log/syslog", max_lines=50)
    """
    try:
        path = Path(filepath).expanduser()
        
        # Security checks
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        if not path.is_file():
            return f"Error: Not a file: {filepath}"
        
        # Block sensitive system files
        sensitive_paths = ['/etc/shadow', '/etc/gshadow', '/root/.ssh']
        if any(str(path).startswith(sp) for sp in sensitive_paths):
            return f"Error: Access to sensitive file blocked: {filepath}"
        
        # Check file size
        size = path.stat().st_size
        if size > 10 * 1024 * 1024:  # 10MB limit
            return f"Error: File too large ({size} bytes). Maximum 10MB"
        
        # Read file
        with open(path, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        lines = lines[:max_lines]
        
        content = ''.join(lines)
        
        result = {
            "file": str(path),
            "size_bytes": size,
            "total_lines": total_lines,
            "showing_lines": len(lines),
            "content": content
        }
        
        return json.dumps(result, indent=2)
        
    except PermissionError:
        return f"Error: Permission denied: {filepath}"
    except Exception as e:
        logger.error(f"File read error: {e}")
        return f"Error: {str(e)}"
