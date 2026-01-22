"""
Ollama local LLM provider.
"""

import logging
from typing import List, Any, Optional, Dict

from zuck.llm.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger('zuck_agent')


class OllamaProvider(BaseLLMProvider):
    """Ollama local provider implementation."""
    
    def __init__(
        self, 
        model_name: str = "llama2",
        temperature: float = 0.3
    ):
        super().__init__(model_name, temperature)
        self._model = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the Ollama model."""
        from langchain_community.chat_models import ChatOllama
        
        self._model = ChatOllama(
            model=self.model_name,
            temperature=self.temperature,
            format="json"  # Request JSON output
        )
        
        logger.info(f"Initialized Ollama: {self.model_name}")
    
    def invoke(self, messages: List[Any]) -> LLMResponse:
        """Send messages to Ollama and get a response."""
        response = self._model.invoke(messages)
        
        # Ollama typically doesn't support native tool calling
        return LLMResponse(
            content=response.content,
            tool_calls=None,
            raw_response=response,
            usage_metadata=None  # Ollama doesn't provide token usage
        )
    
    def bind_tools(self, tools: List[Any]) -> None:
        """Ollama has limited tool support."""
        self._tools = tools
        logger.warning(
            "Ollama has limited tool calling support. "
            "Tools will be called via JSON parsing."
        )
    
    @property
    def supports_tool_calling(self) -> bool:
        """Ollama doesn't support native tool calling."""
        return False
    
    def get_usage_metadata(self, response: Any) -> Optional[Dict[str, int]]:
        """Ollama doesn't provide token usage."""
        return None
