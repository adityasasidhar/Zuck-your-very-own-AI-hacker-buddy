"""
Subdomain finder using certificate transparency logs.
"""

import json
import logging
import re

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def find_subdomains(domain: str) -> str:
    """
    Find subdomains of a domain using certificate transparency logs (crt.sh).
    
    This is a passive reconnaissance technique that doesn't touch the target.
    
    Args:
        domain: Domain to find subdomains for (e.g., "example.com")
        
    Returns:
        List of discovered subdomains
        
    Examples:
        find_subdomains("google.com")
        find_subdomains("github.com")
    """
    try:
        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith(("http://", "https://")):
            domain = re.sub(r'https?://', '', domain).split('/')[0]
        
        # Query crt.sh
        response = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={"User-Agent": "ZuckAgent/1.0"}
        )
        
        if response.status_code != 200:
            return f"Error: crt.sh returned status {response.status_code}"
        
        # Parse results
        try:
            data = response.json()
        except json.JSONDecodeError:
            return "Error: Could not parse crt.sh response"
        
        # Extract unique subdomains
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            # Handle wildcard and multi-line entries
            for subdomain in name.split("\n"):
                subdomain = subdomain.strip().lower()
                if subdomain.startswith("*."):
                    subdomain = subdomain[2:]
                if subdomain.endswith(domain) and subdomain:
                    subdomains.add(subdomain)
        
        # Sort subdomains
        sorted_subdomains = sorted(list(subdomains))
        
        result = {
            "domain": domain,
            "total_found": len(sorted_subdomains),
            "source": "crt.sh (Certificate Transparency)",
            "subdomains": sorted_subdomains[:100]  # Limit to 100
        }
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.Timeout:
        return "Error: Request to crt.sh timed out"
    except requests.exceptions.RequestException as e:
        logger.error(f"Subdomain finder error: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"Subdomain finder error: {e}")
        return f"Error: {str(e)}"


@tool
def dns_subdomain_bruteforce(domain: str, wordlist: str = "common") -> str:
    """
    Attempt to discover subdomains through DNS resolution.
    
    Args:
        domain: Target domain
        wordlist: Wordlist to use - 'common' (50 entries) or 'extended' (200 entries)
        
    Returns:
        Discovered subdomains with IP addresses
        
    Examples:
        dns_subdomain_bruteforce("example.com")
        dns_subdomain_bruteforce("target.com", "extended")
    """
    import socket
    
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "admin", "api", "dev", "staging", "test", "beta", "demo", "portal", "vpn",
        "remote", "m", "mobile", "app", "blog", "forum", "shop", "store", "secure",
        "login", "auth", "sso", "cdn", "static", "assets", "img", "images", "media",
        "docs", "help", "support", "status", "monitor", "git", "gitlab", "jenkins",
        "ci", "build", "deploy", "prod", "production", "internal", "intranet"
    ]
    
    extended_subdomains = common_subdomains + [
        "cloud", "aws", "azure", "gcp", "s3", "backup", "db", "database", "mysql",
        "postgres", "redis", "mongo", "elastic", "kibana", "grafana", "prometheus",
        "logs", "log", "syslog", "nagios", "zabbix", "icinga", "mx", "mx1", "mx2",
        "exchange", "owa", "outlook", "calendar", "drive", "files", "share", "nas",
        "storage", "archive", "old", "new", "v2", "v3", "api2", "api3", "graphql",
        "rest", "soap", "ws", "websocket", "socket", "chat", "im", "slack", "teams",
        "zoom", "meet", "conference", "video", "stream", "live", "radio", "podcast",
        "news", "press", "marketing", "sales", "crm", "erp", "hr", "payroll", "finance",
        "billing", "payment", "checkout", "cart", "order", "orders", "tracking", "ship",
        "delivery", "warehouse", "inventory", "catalog", "search", "solr", "sphinx"
    ]
    
    wordlist_data = extended_subdomains if wordlist == "extended" else common_subdomains
    
    discovered = []
    
    try:
        for sub in wordlist_data:
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                discovered.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                continue  # Subdomain doesn't exist
        
        result = {
            "domain": domain,
            "wordlist": wordlist,
            "attempts": len(wordlist_data),
            "discovered": len(discovered),
            "subdomains": discovered
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"DNS bruteforce error: {e}")
        return f"Error: {str(e)}"
