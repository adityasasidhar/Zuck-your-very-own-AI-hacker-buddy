"""
Google Gemini LLM provider.
"""

import logging
from pathlib import Path
from typing import List, Any, Optional, Dict

from langchain_google_genai import ChatGoogleGenerativeAI

from zuck.llm.base import BaseLLMProvider, LLMResponse

logger = logging.getLogger('zuck_agent')


class GoogleProvider(BaseLLMProvider):
    """Google Gemini provider implementation."""
    
    def __init__(
        self, 
        model_name: str = "gemini-2.5-flash",
        temperature: float = 0.3,
        api_key_file: str = "apikey.txt"
    ):
        super().__init__(model_name, temperature)
        self.api_key_file = api_key_file
        self._model = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the Google Gemini model."""
        api_key = self._load_api_key()
        
        self._model = ChatGoogleGenerativeAI(
            model=self.model_name,
            google_api_key=api_key,
            temperature=self.temperature,
            convert_system_message_to_human=True  # Gemini compatibility
        )
        
        logger.info(f"Initialized Google Gemini: {self.model_name}")
    
    def _load_api_key(self) -> str:
        """Load Google API key from file."""
        api_path = Path(self.api_key_file)
        
        if not api_path.exists():
            logger.critical(f"API key file not found: {self.api_key_file}")
            raise FileNotFoundError(f"API key file not found: {self.api_key_file}")
        
        key = api_path.read_text().strip()
        if not key:
            logger.critical("API key file is empty")
            raise ValueError("API key file is empty")
        
        logger.info("Google API key loaded successfully")
        return key
    
    def invoke(self, messages: List[Any]) -> LLMResponse:
        """Send messages to Gemini and get a response."""
        response = self._model.invoke(messages)
        
        # Extract content
        content = response.content
        if isinstance(content, list):
            # Handle case where content is a list of dicts (e.g., from Gemini)
            text_parts = []
            for part in content:
                if isinstance(part, dict) and 'text' in part:
                    text_parts.append(part['text'])
                elif isinstance(part, str):
                    text_parts.append(part)
            content = "\n".join(text_parts)
        
        # Extract tool calls
        tool_calls = None
        if hasattr(response, 'tool_calls') and response.tool_calls:
            tool_calls = response.tool_calls
        
        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            raw_response=response,
            usage_metadata=self.get_usage_metadata(response)
        )
    
    def bind_tools(self, tools: List[Any]) -> None:
        """Bind tools to the Gemini model."""
        self._tools = tools
        try:
            self._model = self._model.bind_tools(tools)
            logger.info(f"Bound {len(tools)} tools to Google Gemini")
        except AttributeError:
            logger.warning("Google provider does not support tool binding")
    
    def get_usage_metadata(self, response: Any) -> Optional[Dict[str, int]]:
        """Extract token usage from Gemini response."""
        if hasattr(response, 'response_metadata'):
            metadata = response.response_metadata
            if 'usage_metadata' in metadata:
                usage = metadata['usage_metadata']
                return {
                    'prompt_tokens': usage.get('prompt_token_count', 0),
                    'completion_tokens': usage.get('candidates_token_count', 0),
                    'total_tokens': usage.get('total_token_count', 0)
                }
        return None
