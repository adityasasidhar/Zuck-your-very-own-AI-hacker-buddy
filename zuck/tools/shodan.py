"""
Shodan search tool for host and service discovery.
"""

import json
import logging
import os

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

SHODAN_API_URL = "https://api.shodan.io"


def _get_api_key() -> str:
    """Get Shodan API key from environment."""
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        raise ValueError("SHODAN_API_KEY not set in .env file")
    return key


@tool
def shodan_host_lookup(ip: str) -> str:
    """
    Look up information about an IP address using Shodan.
    Returns open ports, services, banners, and vulnerabilities.
    
    Args:
        ip: IP address to look up
    """
    try:
        api_key = _get_api_key()
        
        response = requests.get(
            f"{SHODAN_API_URL}/shodan/host/{ip}",
            params={"key": api_key},
            timeout=15
        )
        
        if response.status_code == 404:
            return f"No information found for IP: {ip}"
        
        response.raise_for_status()
        data = response.json()
        
        result = {
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "services": []
        }
        
        for service in data.get("data", [])[:10]:
            result["services"].append({
                "port": service.get("port"),
                "product": service.get("product", "Unknown"),
                "version": service.get("version", ""),
                "banner": service.get("data", "")[:200]
            })
        
        return json.dumps(result, indent=2)
        
    except ValueError as e:
        return f"Error: {e}"
    except requests.exceptions.RequestException as e:
        return f"Error querying Shodan: {e}"


@tool
def shodan_search(query: str, limit: int = 10) -> str:
    """
    Search Shodan for hosts matching a query.
    
    Args:
        query: Shodan query (e.g., "nginx country:US", "port:3389")
        limit: Maximum results (default: 10)
    """
    try:
        api_key = _get_api_key()
        
        response = requests.get(
            f"{SHODAN_API_URL}/shodan/host/search",
            params={"key": api_key, "query": query, "limit": min(limit, 100)},
            timeout=15
        )
        
        response.raise_for_status()
        data = response.json()
        
        results = {
            "query": query,
            "total": data.get("total", 0),
            "matches": []
        }
        
        for match in data.get("matches", [])[:limit]:
            results["matches"].append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org", "Unknown"),
                "country": match.get("location", {}).get("country_name", "Unknown")
            })
        
        return json.dumps(results, indent=2)
        
    except ValueError as e:
        return f"Error: {e}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
