# python
"""
Wikipedia search tool.
"""

import json
import logging

import wikipedia
from langchain.tools import tool

logger = logging.getLogger('zuck_agent')


@tool
def wikipedia_search(query: str, sentences: int = 10) -> str:
    """
    Search Wikipedia for security concepts and protocols.

    Args:
        query: Search query (security concept, protocol, CVE, etc.)
        sentences: Number of sentences to return (default: 3)

    Returns:
        Wikipedia summary as a JSON string with title and url.
    """
    try:
        wikipedia.set_lang('en')

        try:
            page = wikipedia.page(query)
        except wikipedia.DisambiguationError as e:
            options = e.options[:5]
            return json.dumps({
                "error": "DisambiguationError",
                "message": f"Multiple pages match '{query}'.",
                "options": options
            }, indent=2)
        except wikipedia.PageError:
            results = wikipedia.search(query)
            if not results:
                return f"No Wikipedia page found for '{query}'. Try a more specific query."
            page = wikipedia.page(results[0])

        summary = wikipedia.summary(page.title, sentences=sentences)

        result = {
            "title": page.title,
            "url": page.url,
            "summary": summary
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Wikipedia search error: {e}")
        return f"Error: {str(e)}"
