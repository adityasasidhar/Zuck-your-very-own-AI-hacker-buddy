"""
SSL/TLS and HTTP security header analysis.
"""

import json
import logging
import ssl
import socket
from datetime import datetime
import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def analyze_ssl(hostname: str, port: int = 443) -> str:
    """
    Analyze SSL/TLS certificate and configuration.
    
    Args:
        hostname: Target hostname
        port: Port number (default: 443)
        
    Returns:
        SSL certificate and configuration details
    """
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        
        # Parse certificate
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.now()).days
        
        result = {
            "hostname": hostname,
            "port": port,
            "tls_version": version,
            "cipher": {
                "name": cipher[0],
                "version": cipher[1],
                "bits": cipher[2]
            },
            "certificate": {
                "subject": dict(x[0] for x in cert['subject']),
                "issuer": dict(x[0] for x in cert['issuer']),
                "not_before": str(not_before),
                "not_after": str(not_after),
                "days_remaining": days_remaining,
                "expired": days_remaining < 0
            },
            "warnings": []
        }
        
        # Check for issues
        if days_remaining < 30:
            result["warnings"].append("Certificate expires soon")
        if "TLSv1.0" in version or "TLSv1.1" in version:
            result["warnings"].append("Outdated TLS version")
        
        return json.dumps(result, indent=2)
        
    except ssl.SSLError as e:
        return json.dumps({"error": f"SSL Error: {e}"})
    except Exception as e:
        return f"Error: {e}"


@tool
def analyze_security_headers(url: str) -> str:
    """
    Analyze HTTP security headers for best practices.
    
    Args:
        url: URL to analyze
        
    Returns:
        Security header analysis
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.head(url, timeout=10, allow_redirects=True)
        headers = dict(response.headers)
        
        security_headers = {
            "Strict-Transport-Security": {
                "present": "Strict-Transport-Security" in headers,
                "value": headers.get("Strict-Transport-Security", "Missing"),
                "recommendation": "max-age=31536000; includeSubDomains"
            },
            "Content-Security-Policy": {
                "present": "Content-Security-Policy" in headers,
                "value": headers.get("Content-Security-Policy", "Missing")[:100],
                "recommendation": "default-src 'self'"
            },
            "X-Frame-Options": {
                "present": "X-Frame-Options" in headers,
                "value": headers.get("X-Frame-Options", "Missing"),
                "recommendation": "DENY or SAMEORIGIN"
            },
            "X-Content-Type-Options": {
                "present": "X-Content-Type-Options" in headers,
                "value": headers.get("X-Content-Type-Options", "Missing"),
                "recommendation": "nosniff"
            },
            "X-XSS-Protection": {
                "present": "X-XSS-Protection" in headers,
                "value": headers.get("X-XSS-Protection", "Missing"),
                "recommendation": "1; mode=block"
            }
        }
        
        score = sum(1 for h in security_headers.values() if h["present"])
        
        return json.dumps({
            "url": url,
            "status_code": response.status_code,
            "score": f"{score}/5",
            "headers": security_headers,
            "server": headers.get("Server", "Hidden")
        }, indent=2)
        
    except Exception as e:
        return f"Error: {e}"
