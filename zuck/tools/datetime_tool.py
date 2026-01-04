"""
DateTime operations tool.
"""

import logging
from datetime import datetime, timezone

from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def datetime_tool(operation: str, timestamp: str = None, timezone_str: str = "UTC") -> str:
    """
    Parse timestamps, convert timezones, and calculate time differences.
    
    Args:
        operation: Operation to perform - 'parse', 'convert', 'diff', 'now'
        timestamp: Timestamp string (for parse/convert/diff operations)
        timezone_str: Timezone for conversion (default: UTC)
        
    Returns:
        Formatted datetime information
        
    Examples:
        datetime_tool("now") -> Current UTC time
        datetime_tool("parse", "2024-01-15 10:30:00")
        datetime_tool("diff", "2024-01-15 10:00:00") -> Time since timestamp
    """
    try:
        if operation == "now":
            now = datetime.now(timezone.utc)
            return f"Current UTC time: {now.isoformat()}"
        
        elif operation == "parse":
            if not timestamp:
                return "Error: timestamp required for parse operation"
            
            # Try common timestamp formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%d/%b/%Y:%H:%M:%S",  # Apache log format
                "%Y-%m-%d",
                "%s"  # Unix timestamp
            ]
            
            parsed = None
            for fmt in formats:
                try:
                    if fmt == "%s":
                        parsed = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
                    else:
                        parsed = datetime.strptime(timestamp, fmt)
                    break
                except:
                    continue
            
            if not parsed:
                return f"Error: Could not parse timestamp '{timestamp}'"
            
            return f"Parsed: {parsed.isoformat()}"
        
        elif operation == "diff":
            if not timestamp:
                return "Error: timestamp required for diff operation"
            
            # Parse the timestamp
            formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]
            parsed = None
            for fmt in formats:
                try:
                    parsed = datetime.strptime(timestamp, fmt)
                    break
                except:
                    continue
            
            if not parsed:
                return f"Error: Could not parse timestamp '{timestamp}'"
            
            now = datetime.now()
            diff = now - parsed
            
            return f"Time difference: {diff} ({diff.total_seconds()} seconds)"
        
        else:
            return f"Error: Unknown operation '{operation}'. Use: now, parse, diff"
            
    except Exception as e:
        logger.error(f"DateTime tool error: {e}")
        return f"Error: {str(e)}"
