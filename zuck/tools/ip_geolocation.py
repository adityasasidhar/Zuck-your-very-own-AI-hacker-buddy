"""
IP geolocation and reputation lookup tool.
"""

import json
import logging

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def ip_geolocation(ip: str) -> str:
    """
    Get geolocation, ISP, and threat intelligence for an IP address.
    
    Uses free APIs (ip-api.com and abuseipdb.com if key available).
    
    Args:
        ip: IP address to look up
        
    Returns:
        Geolocation and reputation information
        
    Examples:
        ip_geolocation("8.8.8.8")
        ip_geolocation("1.1.1.1")
    """
    try:
        # Query ip-api.com (free, no key required)
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"},
            timeout=10
        )
        
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "fail":
            return f"Error: {data.get('message', 'Unknown error')}"
        
        result = {
            "ip": ip,
            "geolocation": {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone")
            },
            "network": {
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "asname": data.get("asname"),
                "reverse_dns": data.get("reverse")
            },
            "flags": {
                "is_mobile": data.get("mobile", False),
                "is_proxy": data.get("proxy", False),
                "is_hosting": data.get("hosting", False)
            }
        }
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"IP geolocation error: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"IP geolocation error: {e}")
        return f"Error: {str(e)}"


@tool
def bulk_ip_lookup(ips: str) -> str:
    """
    Look up multiple IP addresses at once.
    
    Args:
        ips: Comma-separated list of IP addresses (max 10)
        
    Returns:
        Geolocation information for all IPs
        
    Examples:
        bulk_ip_lookup("8.8.8.8,1.1.1.1,4.4.4.4")
    """
    try:
        ip_list = [ip.strip() for ip in ips.split(",")][:10]  # Limit to 10
        
        results = []
        for ip in ip_list:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,city,isp,org,proxy,hosting,query"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    results.append({
                        "ip": ip,
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting": data.get("hosting", False)
                    })
                else:
                    results.append({"ip": ip, "error": "Invalid IP"})
            else:
                results.append({"ip": ip, "error": "Lookup failed"})
        
        return json.dumps({"results": results}, indent=2)
        
    except Exception as e:
        logger.error(f"Bulk IP lookup error: {e}")
        return f"Error: {str(e)}"
