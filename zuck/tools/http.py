"""
HTTP request tool.
"""

import json
import logging

import requests
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


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
