"""
Groq LLM provider - Fast inference with open models.
"""

import os
import logging
from typing import List, Any, Optional

from zuck.llm.base import BaseLLMProvider

logger = logging.getLogger('zuck_agent')

# Available Groq models (updated 2026)
GROQ_MODELS = {
    # Production models
    "gpt-oss-120b": "openai/gpt-oss-120b",        # Best quality, 500 tps
    "gpt-oss-20b": "openai/gpt-oss-20b",          # Fast, 1000 tps
    "llama-3.3-70b": "llama-3.3-70b-versatile",   # Classic
    "llama-3.1-8b": "llama-3.1-8b-instant",       # Fastest, 560 tps
    
    # Preview models (Llama 4!)
    "llama-4-maverick": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "llama-4-scout": "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen3-32b": "qwen/qwen3-32b",
    "kimi-k2": "moonshotai/kimi-k2-instruct-0905",
    
    # Compound systems (agentic)
    "compound": "groq/compound",
    "compound-mini": "groq/compound-mini",
}

# Default to Llama 4 Scout (fast, good tool support)
DEFAULT_MODEL = "meta-llama/llama-4-scout-17b-16e-instruct"


class GroqProvider(BaseLLMProvider):
    """Groq LLM provider for fast inference."""
    
    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        temperature: float = 0.3,
        api_key: Optional[str] = None
    ):
        # Resolve short names to full model IDs
        self.model_name = GROQ_MODELS.get(model_name, model_name)
        self.temperature = temperature
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        self.model = None
        self.tools = []
        
        if not self.api_key:
            raise ValueError("GROQ_API_KEY not set in .env file")
        
        self._initialize()
    
    def _initialize(self):
        """Initialize the Groq model."""
        try:
            from langchain_groq import ChatGroq
            
            self.model = ChatGroq(
                model=self.model_name,
                temperature=self.temperature,
                api_key=self.api_key,
            )
            logger.info(f"Initialized Groq: {self.model_name}")
            
        except ImportError:
            raise ImportError("langchain-groq not installed. Run: pip install langchain-groq")
        except Exception as e:
            logger.error(f"Failed to initialize Groq: {e}")
            raise
    
    def bind_tools(self, tools: List[Any]) -> None:
        """Bind tools to the model."""
        self.tools = tools
        if self.model and tools:
            self.model = self.model.bind_tools(tools)
            logger.info(f"Bound {len(tools)} tools to Groq")
    
    def invoke(self, messages: List[Any]) -> Any:
        """Invoke the model."""
        if not self.model:
            raise RuntimeError("Model not initialized")
        return self.model.invoke(messages)
    
    def get_model_name(self) -> str:
        return self.model_name
    
    def get_provider_name(self) -> str:
        return "groq"
