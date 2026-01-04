"""
Anthropic Claude LLM provider.
"""

import os
import logging
from typing import List, Any, Optional, Dict

from langchain_anthropic import ChatAnthropic

from zuck.llm.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger('zuck_agent')


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude provider implementation."""
    
    def __init__(
        self, 
        model_name: str = "claude-3-sonnet-20240229",
        temperature: float = 0.3,
        api_key: Optional[str] = None
    ):
        super().__init__(model_name, temperature)
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self._model = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the Anthropic model."""
        if not self.api_key:
            raise ValueError(
                "Anthropic API key not found. "
                "Set anthropic_api_key in config or ANTHROPIC_API_KEY env var"
            )
        
        self._model = ChatAnthropic(
            model=self.model_name,
            api_key=self.api_key,
            temperature=self.temperature
        )
        
        logger.info(f"Initialized Anthropic Claude: {self.model_name}")
    
    def invoke(self, messages: List[Any]) -> LLMResponse:
        """Send messages to Anthropic and get a response."""
        response = self._model.invoke(messages)
        
        # Extract tool calls
        tool_calls = None
        if hasattr(response, 'tool_calls') and response.tool_calls:
            tool_calls = response.tool_calls
        
        return LLMResponse(
            content=response.content,
            tool_calls=tool_calls,
            raw_response=response,
            usage_metadata=self.get_usage_metadata(response)
        )
    
    def bind_tools(self, tools: List[Any]) -> None:
        """Bind tools to the Anthropic model."""
        self._tools = tools
        try:
            self._model = self._model.bind_tools(tools)
            logger.info(f"Bound {len(tools)} tools to Anthropic Claude")
        except AttributeError:
            logger.warning("Anthropic provider does not support tool binding")
    
    def get_usage_metadata(self, response: Any) -> Optional[Dict[str, int]]:
        """Extract token usage from Anthropic response."""
        if hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            if 'usage' in metadata:
                usage = metadata['usage']
                prompt_tokens = usage.get('input_tokens', 0)
                completion_tokens = usage.get('output_tokens', 0)
                return {
                    'prompt_tokens': prompt_tokens,
                    'completion_tokens': completion_tokens,
                    'total_tokens': prompt_tokens + completion_tokens
                }
        return None
