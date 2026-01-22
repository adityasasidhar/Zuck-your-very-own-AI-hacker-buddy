"""
Factory for creating LLM providers.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from zuck.core.config import AgentConfig
    from zuck.llm.base import BaseLLMProvider

logger = logging.getLogger('zuck_agent')


def create_provider(config: "AgentConfig") -> "BaseLLMProvider":
    """
    Factory method to create the appropriate LLM provider based on configuration.
    
    Args:
        config: AgentConfig with provider settings
        
    Returns:
        Configured LLM provider instance
        
    Raises:
        ValueError: If provider is not supported
    """
    provider = config.provider.lower()
    
    logger.info(f"Creating LLM provider: {provider}")
    
    if provider == "google":
        from zuck.llm.google import GoogleProvider
        return GoogleProvider(
            model_name=config.model_name or "gemini-2.5-flash",
            temperature=config.temperature,
            api_key=config.google_api_key
        )
    
    elif provider == "openai":
        from zuck.llm.openai import OpenAIProvider
        return OpenAIProvider(
            model_name=config.model_name or "gpt-4",
            temperature=config.temperature,
            api_key=config.openai_api_key
        )
    
    elif provider == "anthropic":
        from zuck.llm.anthropic import AnthropicProvider
        return AnthropicProvider(
            model_name=config.model_name or "claude-3-sonnet-20240229",
            temperature=config.temperature,
            api_key=config.anthropic_api_key
        )
    
    elif provider == "ollama":
        from zuck.llm.ollama import OllamaProvider
        return OllamaProvider(
            model_name=config.model_name or "llama3",
            temperature=config.temperature
        )
    
    elif provider == "groq":
        from zuck.llm.groq import GroqProvider
        return GroqProvider(
            model_name=config.model_name or "llama-3.3-70b-versatile",
            temperature=config.temperature,
            api_key=config.groq_api_key
        )
    
    else:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            "Choose from: google, openai, anthropic, ollama, groq"
        )
