"""
OpenAI LLM provider.
"""

import os
import logging
from typing import List, Any, Optional, Dict

from langchain_openai import ChatOpenAI

from zuck.llm.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger('zuck_agent')


class OpenAIProvider(BaseLLMProvider):
    """OpenAI provider implementation."""
    
    def __init__(
        self, 
        model_name: str = "gpt-4",
        temperature: float = 0.3,
        api_key: Optional[str] = None
    ):
        super().__init__(model_name, temperature)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self._model = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the OpenAI model."""
        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. "
                "Set openai_api_key in config or OPENAI_API_KEY env var"
            )
        
        self._model = ChatOpenAI(
            model=self.model_name,
            api_key=self.api_key,
            temperature=self.temperature,
            model_kwargs={"response_format": {"type": "json_object"}}
        )
        
        logger.info(f"Initialized OpenAI: {self.model_name}")
    
    def invoke(self, messages: List[Any]) -> LLMResponse:
        """Send messages to OpenAI and get a response."""
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
        """Bind tools to the OpenAI model."""
        self._tools = tools
        try:
            self._model = self._model.bind_tools(tools)
            logger.info(f"Bound {len(tools)} tools to OpenAI")
        except AttributeError:
            logger.warning("OpenAI provider does not support tool binding")
    
    def get_usage_metadata(self, response: Any) -> Optional[Dict[str, int]]:
        """Extract token usage from OpenAI response."""
        if hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            if 'token_usage' in metadata:
                usage = metadata['token_usage']
                return {
                    'prompt_tokens': usage.get('prompt_tokens', 0),
                    'completion_tokens': usage.get('completion_tokens', 0),
                    'total_tokens': usage.get('total_tokens', 0)
                }
        return None
