"""
Abstract base class for LLM providers.
"""

from abc import ABC, abstractmethod
from typing import List, Any, Optional, Dict
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Standardized response from LLM providers."""
    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None
    raw_response: Any = None
    usage_metadata: Optional[Dict[str, int]] = None


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, model_name: str, temperature: float = 0.3):
        self.model_name = model_name
        self.temperature = temperature
        self._tools = []
    
    @abstractmethod
    def invoke(self, messages: List[Any]) -> LLMResponse:
        """
        Send messages to the LLM and get a response.
        
        Args:
            messages: List of message objects (HumanMessage, AIMessage, etc.)
            
        Returns:
            LLMResponse with content and optional tool calls
        """
        pass
    
    @abstractmethod
    def bind_tools(self, tools: List[Any]) -> None:
        """
        Bind tools to the provider for tool calling.
        
        Args:
            tools: List of LangChain tool objects
        """
        pass
    
    @property
    def supports_tool_calling(self) -> bool:
        """Whether this provider supports native tool calling."""
        return True
    
    def get_usage_metadata(self, response: Any) -> Optional[Dict[str, int]]:
        """
        Extract token usage from provider response.
        
        Args:
            response: Raw response from the provider
            
        Returns:
            Dict with prompt_tokens, completion_tokens, total_tokens
        """
        return None
