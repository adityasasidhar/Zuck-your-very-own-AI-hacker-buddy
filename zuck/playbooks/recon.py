"""
Reconnaissance playbook - automated target enumeration.
"""

import json
from langchain.tools import tool


@tool
def run_recon_playbook(target: str, depth: str = "basic") -> str:
    """
    Run automated reconnaissance playbook on a target.
    
    Performs: subdomain enum, port scan, technology detection, OSINT.
    
    Args:
        target: Target domain or IP
        depth: Scan depth - basic, standard, deep
        
    Returns:
        Comprehensive recon results
        
    Examples:
        run_recon_playbook("example.com")
        run_recon_playbook("10.10.10.1", "deep")
    """
    from zuck.tools.subdomain_finder import find_subdomains
    from zuck.tools.port_scanner import port_scan
    from zuck.tools.dns import dns_lookup
    from zuck.tools.whois import whois_lookup
    from zuck.tools.ssl_analyzer import analyze_ssl, analyze_security_headers
    
    results = {"target": target, "depth": depth, "phases": {}}
    
    # Phase 1: DNS & WHOIS
    print(f"\n📋 Phase 1: DNS & WHOIS for {target}")
    try:
        results["phases"]["dns"] = json.loads(dns_lookup.invoke({"domain": target}))
    except:
        results["phases"]["dns"] = "Error"
    
    try:
        results["phases"]["whois"] = json.loads(whois_lookup.invoke({"domain": target}))
    except:
        results["phases"]["whois"] = "Error"
    
    # Phase 2: Subdomain enumeration
    print(f"📋 Phase 2: Subdomain enumeration")
    try:
        results["phases"]["subdomains"] = json.loads(find_subdomains.invoke({"domain": target}))
    except:
        results["phases"]["subdomains"] = "Error"
    
    # Phase 3: Port scanning
    print(f"📋 Phase 3: Port scanning")
    ports = "common" if depth == "basic" else "top100"
    try:
        results["phases"]["ports"] = json.loads(port_scan.invoke({"target": target, "ports": ports}))
    except:
        results["phases"]["ports"] = "Error"
    
    # Phase 4: SSL/TLS analysis
    if depth in ["standard", "deep"]:
        print(f"📋 Phase 4: SSL/TLS analysis")
        try:
            results["phases"]["ssl"] = json.loads(analyze_ssl.invoke({"hostname": target}))
        except:
            results["phases"]["ssl"] = "Error"
        
        try:
            results["phases"]["headers"] = json.loads(analyze_security_headers.invoke({"url": target}))
        except:
            results["phases"]["headers"] = "Error"
    
    # Summary
    results["summary"] = {
        "subdomains_found": results["phases"].get("subdomains", {}).get("total_found", 0),
        "open_ports": results["phases"].get("ports", {}).get("open_ports", 0),
        "ssl_days_remaining": results["phases"].get("ssl", {}).get("certificate", {}).get("days_remaining", "N/A")
    }
    
    return json.dumps(results, indent=2)
