"""
VirusTotal lookup tool.
"""

import os
import re
import json
import logging
import base64

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def virustotal_lookup(resource: str, resource_type: str = "auto") -> str:
    """
    Check file hash, URL, domain, or IP reputation using VirusTotal.
    
    Args:
        resource: Hash, URL, domain, or IP to check
        resource_type: Type - 'hash', 'url', 'domain', 'ip', or 'auto'
    """
    try:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return "Error: VIRUSTOTAL_API_KEY not set in .env file"
        
        headers = {"x-apikey": api_key}
        
        # Auto-detect type
        if resource_type == "auto":
            if re.match(r'^[a-fA-F0-9]{32,64}$', resource):
                resource_type = "hash"
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', resource):
                resource_type = "ip"
            elif resource.startswith(('http://', 'https://')):
                resource_type = "url"
            else:
                resource_type = "domain"
        
        # Build URL
        if resource_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{resource}"
        elif resource_type == "url":
            url_id = base64.urlsafe_b64encode(resource.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif resource_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{resource}"
        elif resource_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource}"
        else:
            return f"Error: Unknown type '{resource_type}'"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return f"Not found in VirusTotal: {resource}"
        
        response.raise_for_status()
        data = response.json()
        
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        result = {
            "resource": resource,
            "type": resource_type,
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "harmless": stats.get('harmless', 0),
            "reputation": attrs.get('reputation', 'N/A')
        }
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
