"""
IOC (Indicators of Compromise) extraction tool.
"""

import json
import logging
import re
import hashlib
from pathlib import Path
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

# IOC patterns
IOC_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "ipv6": r'(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "bitcoin": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    "cve": r'CVE-\d{4}-\d{4,}',
}


@tool
def extract_iocs(text: str) -> str:
    """
    Extract IOCs from text (IPs, domains, hashes, emails, URLs).
    
    Args:
        text: Text to extract IOCs from
        
    Returns:
        Extracted IOCs by type
    """
    try:
        iocs = {}
        
        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
            if matches:
                iocs[ioc_type] = matches[:50]  # Limit
        
        # Filter out common false positives
        if "domain" in iocs:
            iocs["domain"] = [d for d in iocs["domain"] 
                             if not d.endswith(('.png', '.jpg', '.gif', '.css', '.js'))]
        
        return json.dumps({
            "total_iocs": sum(len(v) for v in iocs.values()),
            "iocs": iocs
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"


@tool
def extract_iocs_from_file(filepath: str) -> str:
    """
    Extract IOCs from a file.
    
    Args:
        filepath: Path to file
        
    Returns:
        Extracted IOCs
    """
    try:
        path = Path(filepath).expanduser()
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        # Check file size
        if path.stat().st_size > 10 * 1024 * 1024:
            return "Error: File too large (max 10MB)"
        
        content = path.read_text(errors='ignore')
        return extract_iocs.invoke({"text": content})
        
    except Exception as e:
        return f"Error: {e}"


@tool
def analyze_file_hashes(filepath: str) -> str:
    """
    Calculate file hashes for malware analysis.
    
    Args:
        filepath: Path to file
        
    Returns:
        MD5, SHA1, SHA256 hashes
    """
    try:
        path = Path(filepath).expanduser()
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        if path.stat().st_size > 100 * 1024 * 1024:
            return "Error: File too large (max 100MB)"
        
        content = path.read_bytes()
        
        result = {
            "file": str(path),
            "size_bytes": len(content),
            "hashes": {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "sha256": hashlib.sha256(content).hexdigest()
            },
            "virustotal_url": f"https://www.virustotal.com/gui/search/{hashlib.sha256(content).hexdigest()}"
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return f"Error: {e}"
