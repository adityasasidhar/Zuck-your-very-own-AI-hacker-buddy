import re
import json
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import logging
import requests
import dns.resolver
import whois as python_whois
import wikipediaapi

from langchain.tools import tool
from langchain_experimental.tools import PythonREPLTool

logger = logging.getLogger('zuck_agent')

# Session memory storage
_session_memory: Dict[str, Any] = {}


# ==================== 1. Calculator Tool ====================

@tool
def calculator(expression: str) -> str:
    """
    Evaluate mathematical expressions and perform network calculations.
    
    Supports:
    - Basic math: 2+2, 10*5, 100/4
    - Subnet calculations: "192.168.1.0/24 size", "10.0.0.0/16 range"
    - Hex/decimal conversions: "0xFF to decimal", "255 to hex"
    - Binary conversions: "0b11111111 to decimal", "255 to binary"
    - Port calculations: "1024 + 80"
    
    Args:
        expression: Mathematical expression or network calculation
        
    Returns:
        Calculation result as string
        
    Examples:
        calculator("2 + 2") -> "4"
        calculator("192.168.1.0/24 size") -> "256 addresses"
        calculator("0xFF to decimal") -> "255"
    """
    try:
        expression = expression.strip().lower()
        
        # Subnet calculations
        if '/' in expression and any(word in expression for word in ['size', 'range', 'hosts', 'network']):
            # Extract CIDR notation
            cidr_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', expression)
            if cidr_match:
                network = ipaddress.ip_network(cidr_match.group(1), strict=False)
                result = {
                    "network": str(network.network_address),
                    "netmask": str(network.netmask),
                    "broadcast": str(network.broadcast_address),
                    "first_host": str(list(network.hosts())[0]) if network.num_addresses > 2 else "N/A",
                    "last_host": str(list(network.hosts())[-1]) if network.num_addresses > 2 else "N/A",
                    "total_addresses": network.num_addresses,
                    "usable_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0
                }
                return json.dumps(result, indent=2)
        
        # Hex to decimal
        if 'to decimal' in expression or 'to dec' in expression:
            hex_match = re.search(r'0x([0-9a-f]+)', expression)
            if hex_match:
                return str(int(hex_match.group(1), 16))
        
        # Decimal to hex
        if 'to hex' in expression:
            dec_match = re.search(r'(\d+)', expression)
            if dec_match:
                return hex(int(dec_match.group(1)))
        
        # Binary to decimal
        if 'to decimal' in expression or 'to dec' in expression:
            bin_match = re.search(r'0b([01]+)', expression)
            if bin_match:
                return str(int(bin_match.group(1), 2))
        
        # Decimal to binary
        if 'to binary' in expression or 'to bin' in expression:
            dec_match = re.search(r'(\d+)', expression)
            if dec_match:
                return bin(int(dec_match.group(1)))
        
        # Basic math evaluation (safe eval)
        # Remove any non-math characters for safety
        safe_expr = re.sub(r'[^0-9+\-*/().\s]', '', expression)
        if safe_expr:
            result = eval(safe_expr, {"__builtins__": {}}, {})
            return str(result)
        
        return "Unable to parse expression. Try: '2+2', '192.168.1.0/24 size', '0xFF to decimal'"
        
    except Exception as e:
        logger.error(f"Calculator error: {e}")
        return f"Error: {str(e)}"


# ==================== 2. VirusTotal Tool ====================

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


# ==================== 3. DateTime Tool ====================

@tool
def datetime_tool(operation: str, timestamp: str = None, timezone_str: str = "UTC") -> str:
    """
    Parse timestamps, convert timezones, and calculate time differences.
    
    Args:
        operation: Operation to perform - 'parse', 'convert', 'diff', 'now'
        timestamp: Timestamp string (for parse/convert/diff operations)
        timezone_str: Timezone for conversion (default: UTC)
        
    Returns:
        Formatted datetime information
        
    Examples:
        datetime_tool("now") -> Current UTC time
        datetime_tool("parse", "2024-01-15 10:30:00")
        datetime_tool("diff", "2024-01-15 10:00:00") -> Time since timestamp
    """
    try:
        if operation == "now":
            now = datetime.now(timezone.utc)
            return f"Current UTC time: {now.isoformat()}"
        
        elif operation == "parse":
            if not timestamp:
                return "Error: timestamp required for parse operation"
            
            # Try common timestamp formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%d/%b/%Y:%H:%M:%S",  # Apache log format
                "%Y-%m-%d",
                "%s"  # Unix timestamp
            ]
            
            parsed = None
            for fmt in formats:
                try:
                    if fmt == "%s":
                        parsed = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
                    else:
                        parsed = datetime.strptime(timestamp, fmt)
                    break
                except:
                    continue
            
            if not parsed:
                return f"Error: Could not parse timestamp '{timestamp}'"
            
            return f"Parsed: {parsed.isoformat()}"
        
        elif operation == "diff":
            if not timestamp:
                return "Error: timestamp required for diff operation"
            
            # Parse the timestamp
            formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]
            parsed = None
            for fmt in formats:
                try:
                    parsed = datetime.strptime(timestamp, fmt)
                    break
                except:
                    continue
            
            if not parsed:
                return f"Error: Could not parse timestamp '{timestamp}'"
            
            now = datetime.now()
            diff = now - parsed
            
            return f"Time difference: {diff} ({diff.total_seconds()} seconds)"
        
        else:
            return f"Error: Unknown operation '{operation}'. Use: now, parse, diff"
            
    except Exception as e:
        logger.error(f"DateTime tool error: {e}")
        return f"Error: {str(e)}"


# ==================== 4. Memory Tool ====================

@tool
def memory_store(action: str, key: str = None, value: str = None) -> str:
    """
    Store and retrieve findings during the session for context building.
    
    Args:
        action: Action to perform - 'store', 'retrieve', 'list', 'clear'
        key: Key for storage/retrieval
        value: Value to store (for 'store' action)
        
    Returns:
        Result of the memory operation
        
    Examples:
        memory_store("store", "scan_result", "Found 5 open ports")
        memory_store("retrieve", "scan_result")
        memory_store("list")
    """
    global _session_memory
    
    try:
        if action == "store":
            if not key or value is None:
                return "Error: Both key and value required for store action"
            _session_memory[key] = value
            return f"Stored: {key} = {value[:100]}..." if len(value) > 100 else f"Stored: {key} = {value}"
        
        elif action == "retrieve":
            if not key:
                return "Error: Key required for retrieve action"
            if key in _session_memory:
                return f"{key}: {_session_memory[key]}"
            else:
                return f"Key '{key}' not found in memory"
        
        elif action == "list":
            if not _session_memory:
                return "Memory is empty"
            keys = list(_session_memory.keys())
            return f"Stored keys ({len(keys)}): {', '.join(keys)}"
        
        elif action == "clear":
            count = len(_session_memory)
            _session_memory.clear()
            return f"Cleared {count} items from memory"
        
        else:
            return f"Error: Unknown action '{action}'. Use: store, retrieve, list, clear"
            
    except Exception as e:
        logger.error(f"Memory tool error: {e}")
        return f"Error: {str(e)}"


# ==================== 5. File Reader Tool ====================

@tool
def read_file(filepath: str, max_lines: int = 100) -> str:
    """
    Read and analyze configuration files and logs safely.
    
    Args:
        filepath: Path to the file to read
        max_lines: Maximum number of lines to read (default: 100)
        
    Returns:
        File content with metadata
        
    Examples:
        read_file("/etc/hosts")
        read_file("/var/log/syslog", max_lines=50)
    """
    try:
        path = Path(filepath).expanduser()
        
        # Security checks
        if not path.exists():
            return f"Error: File not found: {filepath}"
        
        if not path.is_file():
            return f"Error: Not a file: {filepath}"
        
        # Block sensitive system files
        sensitive_paths = ['/etc/shadow', '/etc/gshadow', '/root/.ssh']
        if any(str(path).startswith(sp) for sp in sensitive_paths):
            return f"Error: Access to sensitive file blocked: {filepath}"
        
        # Check file size
        size = path.stat().st_size
        if size > 10 * 1024 * 1024:  # 10MB limit
            return f"Error: File too large ({size} bytes). Maximum 10MB"
        
        # Read file
        with open(path, 'r', errors='ignore') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        lines = lines[:max_lines]
        
        content = ''.join(lines)
        
        result = {
            "file": str(path),
            "size_bytes": size,
            "total_lines": total_lines,
            "showing_lines": len(lines),
            "content": content
        }
        
        return json.dumps(result, indent=2)
        
    except PermissionError:
        return f"Error: Permission denied: {filepath}"
    except Exception as e:
        logger.error(f"File read error: {e}")
        return f"Error: {str(e)}"


# ==================== 6. HTTP Request Tool ====================

@tool
def http_request(url: str, method: str = "GET", headers: str = None) -> str:
    """
    Make HTTP requests to test APIs and analyze headers.
    
    Args:
        url: URL to request
        method: HTTP method (GET, POST, HEAD, OPTIONS)
        headers: Optional JSON string of headers to send
        
    Returns:
        Response status, headers, and preview
        
    Examples:
        http_request("https://example.com")
        http_request("https://api.example.com/status", "GET")
    """
    try:
        # Parse custom headers if provided
        custom_headers = {}
        if headers:
            try:
                custom_headers = json.loads(headers)
            except:
                return "Error: Invalid JSON for headers"
        
        # Make request
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=custom_headers,
            timeout=10,
            allow_redirects=True
        )
        
        # Extract information
        result = {
            "url": url,
            "method": method.upper(),
            "status_code": response.status_code,
            "status_text": response.reason,
            "headers": dict(response.headers),
            "content_type": response.headers.get('Content-Type', 'N/A'),
            "content_length": len(response.content),
            "response_preview": response.text[:500] if response.text else "No content"
        }
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.Timeout:
        return f"Error: Request timeout for {url}"
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP request error: {e}")
        return f"Error: {str(e)}"
    except Exception as e:
        logger.error(f"HTTP tool error: {e}")
        return f"Error: {str(e)}"


# ==================== 7. DNS Lookup Tool ====================

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


# ==================== 8. WHOIS Tool ====================

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


# ==================== 9. Python REPL Tool ====================

def get_python_repl_tool():
    """
    Get Python REPL tool for executing code.
    
    Returns:
        PythonREPLTool instance
        
    Note: This tool allows Python code execution. Use with caution.
    """
    return PythonREPLTool(
        description="""
        Execute Python code for data analysis and parsing.
        Useful for: parsing complex data, calculations, data transformations.
        Input should be valid Python code.
        Returns the output of the code execution.
        """
    )


# ==================== 10. Wikipedia Tool ====================

@tool
def wikipedia_search(query: str, sentences: int = 3) -> str:
    """
    Search Wikipedia for security concepts and protocols.
    
    Args:
        query: Search query (security concept, protocol, CVE, etc.)
        sentences: Number of sentences to return (default: 3)
        
    Returns:
        Wikipedia summary
        
    Examples:
        wikipedia_search("SQL injection")
        wikipedia_search("TLS protocol")
        wikipedia_search("Cross-site scripting")
    """
    try:
        wiki = wikipediaapi.Wikipedia('en')
        page = wiki.page(query)
        
        if not page.exists():
            # Try searching
            return f"No Wikipedia page found for '{query}'. Try a more specific query."
        
        # Get summary
        summary = page.summary[:1000]  # Limit to 1000 chars
        
        result = {
            "title": page.title,
            "url": page.fullurl,
            "summary": summary
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        logger.error(f"Wikipedia search error: {e}")
        return f"Error: {str(e)}"


# ==================== Tool List Export ====================

def get_all_tools():
    """Get list of all available tools"""
    return [
        calculator,
        virustotal_lookup,
        datetime_tool,
        memory_store,
        read_file,
        http_request,
        dns_lookup,
        whois_lookup,
        get_python_repl_tool(),
        wikipedia_search
    ]
