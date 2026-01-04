"""
Google Gemini LLM provider.
"""

import os
import logging
from typing import List, Any, Optional

from zuck.llm.base import BaseLLMProvider

logger = logging.getLogger('zuck_agent')


class GoogleProvider(BaseLLMProvider):
    """Google Gemini LLM provider."""
    
    def __init__(
        self,
        model_name: str = "gemini-2.5-flash",
        temperature: float = 0.3,
        api_key: Optional[str] = None
    ):
        self.model_name = model_name
        self.temperature = temperature
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model = None
        self.tools = []
        
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY not set in .env file")
        
        self._initialize()
    
    def _initialize(self):
        """Initialize the Google Gemini model."""
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            
            self.model = ChatGoogleGenerativeAI(
                model=self.model_name,
                temperature=self.temperature,
                google_api_key=self.api_key,
            )
            logger.info(f"Initialized Google Gemini: {self.model_name}")
            
        except ImportError:
            raise ImportError("langchain-google-genai not installed")
        except Exception as e:
            logger.error(f"Failed to initialize Google: {e}")
            raise
    
    def bind_tools(self, tools: List[Any]) -> None:
        """Bind tools to the model."""
        self.tools = tools
        if self.model and tools:
            self.model = self.model.bind_tools(tools)
            logger.info(f"Bound {len(tools)} tools to Google Gemini")
    
    def invoke(self, messages: List[Any]) -> Any:
        """Invoke the model."""
        if not self.model:
            raise RuntimeError("Model not initialized")
        return self.model.invoke(messages)
    
    def get_model_name(self) -> str:
        return self.model_name
    
    def get_provider_name(self) -> str:
        return "google"
