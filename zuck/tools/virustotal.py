"""
VirusTotal lookup tool.
"""

import re
import json
import logging
from pathlib import Path

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def virustotal_lookup(resource: str, resource_type: str = "auto") -> str:
    """
    Check file hash, URL, domain, or IP reputation using VirusTotal API.
    
    Args:
        resource: The resource to check (hash, URL, domain, or IP)
        resource_type: Type of resource - 'hash', 'url', 'domain', 'ip', or 'auto' (default)
        
    Returns:
        Reputation analysis from VirusTotal
        
    Examples:
        virustotal_lookup("44d88612fea8a8f36de82e1278abb02f", "hash")
        virustotal_lookup("example.com", "domain")
        virustotal_lookup("8.8.8.8", "ip")
    """
    try:
        # Load API key
        api_key_file = Path("virustotalapikey.txt")
        if not api_key_file.exists():
            return "Error: VirusTotal API key file not found (virustotalapikey.txt)"
        
        api_key = api_key_file.read_text().strip()
        if not api_key:
            return "Error: VirusTotal API key is empty"
        
        headers = {"x-apikey": api_key}
        
        # Auto-detect resource type
        if resource_type == "auto":
            if re.match(r'^[a-fA-F0-9]{32,64}$', resource):
                resource_type = "hash"
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', resource):
                resource_type = "ip"
            elif resource.startswith(('http://', 'https://')):
                resource_type = "url"
            else:
                resource_type = "domain"
        
        # Make API request based on type
        if resource_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{resource}"
        elif resource_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(resource.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif resource_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{resource}"
        elif resource_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource}"
        else:
            return f"Error: Unknown resource type '{resource_type}'"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return f"Resource not found in VirusTotal database: {resource}"
        
        response.raise_for_status()
        data = response.json()
        
        # Extract relevant information
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        result = {
            "resource": resource,
            "type": resource_type,
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "undetected": stats.get('undetected', 0),
            "reputation": attributes.get('reputation', 'N/A'),
            "last_analysis_date": attributes.get('last_analysis_date', 'N/A')
        }
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API error: {e}")
        return f"Error querying VirusTotal: {str(e)}"
    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return f"Error: {str(e)}"
