"""
Wikipedia search tool.
"""

import json
import logging

import wikipediaapi
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


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
