"""
DNS lookup tool.
"""

import json
import logging

import dns.resolver
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """
    Query DNS records programmatically.
    
    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, TXT, NS, CNAME, SOA)
        
    Returns:
        DNS query results
        
    Examples:
        dns_lookup("google.com", "A")
        dns_lookup("example.com", "MX")
        dns_lookup("example.com", "TXT")
    """
    try:
        record_type = record_type.upper()
        
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        
        records = []
        for rdata in answers:
            if record_type == "MX":
                records.append(f"{rdata.preference} {rdata.exchange}")
            elif record_type == "SOA":
                records.append(f"mname={rdata.mname} rname={rdata.rname}")
            else:
                records.append(str(rdata))
        
        result = {
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "count": len(records)
        }
        
        return json.dumps(result, indent=2)
        
    except dns.resolver.NXDOMAIN:
        return f"Error: Domain not found: {domain}"
    except dns.resolver.NoAnswer:
        return f"No {record_type} records found for {domain}"
    except Exception as e:
        logger.error(f"DNS lookup error: {e}")
        return f"Error: {str(e)}"
