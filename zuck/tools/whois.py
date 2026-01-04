"""
WHOIS lookup tool.
"""

import json
import logging

import whois as python_whois
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def whois_lookup(domain: str) -> str:
    """
    Get domain registration and ownership information.
    
    Args:
        domain: Domain name to look up
        
    Returns:
        WHOIS information
        
    Examples:
        whois_lookup("google.com")
        whois_lookup("example.org")
    """
    try:
        w = python_whois.whois(domain)
        
        result = {
            "domain": domain,
            "registrar": w.registrar if hasattr(w, 'registrar') else "N/A",
            "creation_date": str(w.creation_date) if hasattr(w, 'creation_date') else "N/A",
            "expiration_date": str(w.expiration_date) if hasattr(w, 'expiration_date') else "N/A",
            "name_servers": w.name_servers if hasattr(w, 'name_servers') else [],
            "status": w.status if hasattr(w, 'status') else "N/A",
            "emails": w.emails if hasattr(w, 'emails') else []
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"WHOIS lookup error: {e}")
        return f"Error: {str(e)}"
