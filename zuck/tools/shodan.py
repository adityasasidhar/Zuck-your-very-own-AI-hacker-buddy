"""
Shodan search tool for host and service discovery.
"""

import json
import logging
from pathlib import Path

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')

SHODAN_API_URL = "https://api.shodan.io"


def _load_shodan_api_key() -> str:
    """Load Shodan API key from file."""
    api_key_file = Path("shodanapikey.txt")
    if not api_key_file.exists():
        raise FileNotFoundError("Shodan API key file not found (shodanapikey.txt)")
    
    key = api_key_file.read_text().strip()
    if not key:
        raise ValueError("Shodan API key is empty")
    
    return key


@tool
def shodan_host_lookup(ip: str) -> str:
    """
    Look up information about a specific IP address using Shodan.
    
    Returns open ports, services, banners, and vulnerabilities.
    
    Args:
        ip: IP address to look up
        
    Returns:
        Host information from Shodan
        
    Examples:
        shodan_host_lookup("8.8.8.8")
    """
    try:
        api_key = _load_shodan_api_key()
        
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
            "isp": data.get("isp", "Unknown"),
            "asn": data.get("asn", "Unknown"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "last_update": data.get("last_update", "Unknown"),
            "services": []
        }
        
        # Extract service information
        for service in data.get("data", [])[:10]:  # Limit to 10 services
            result["services"].append({
                "port": service.get("port"),
                "transport": service.get("transport"),
                "product": service.get("product", "Unknown"),
                "version": service.get("version", ""),
                "banner": service.get("data", "")[:200]  # Truncate banner
            })
        
        return json.dumps(result, indent=2)
        
    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Shodan API error: {e}")
        return f"Error querying Shodan: {str(e)}"
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return f"Error: {str(e)}"


@tool
def shodan_search(query: str, limit: int = 10) -> str:
    """
    Search Shodan for hosts matching a query.
    
    Args:
        query: Shodan search query (e.g., "apache country:US", "port:22", "vuln:CVE-2021-44228")
        limit: Maximum number of results (default: 10)
        
    Returns:
        Search results from Shodan
        
    Examples:
        shodan_search("nginx country:IN")
        shodan_search("port:3389 os:windows")
        shodan_search("vuln:CVE-2021-44228")
    """
    try:
        api_key = _load_shodan_api_key()
        
        response = requests.get(
            f"{SHODAN_API_URL}/shodan/host/search",
            params={
                "key": api_key,
                "query": query,
                "limit": min(limit, 100)
            },
            timeout=15
        )
        
        response.raise_for_status()
        data = response.json()
        
        results = {
            "query": query,
            "total_results": data.get("total", 0),
            "matches": []
        }
        
        for match in data.get("matches", [])[:limit]:
            results["matches"].append({
                "ip": match.get("ip_str"),
                "port": match.get("port"),
                "org": match.get("org", "Unknown"),
                "country": match.get("location", {}).get("country_name", "Unknown"),
                "product": match.get("product", "Unknown"),
                "banner": match.get("data", "")[:150]
            })
        
        return json.dumps(results, indent=2)
        
    except FileNotFoundError as e:
        return f"Error: {str(e)}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Shodan search error: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return f"Error: {str(e)}"
