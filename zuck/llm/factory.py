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
            model_name=config.model_name,
            temperature=config.temperature,
            api_key_file=config.api_key_file
        )
    
    elif provider == "openai":
        from zuck.llm.openai import OpenAIProvider
        return OpenAIProvider(
            model_name=config.model_name,
            temperature=config.temperature,
            api_key=config.openai_api_key
        )
    
    elif provider == "anthropic":
        from zuck.llm.anthropic import AnthropicProvider
        return AnthropicProvider(
            model_name=config.model_name,
            temperature=config.temperature,
            api_key=config.anthropic_api_key
        )
    
    elif provider == "ollama":
        from zuck.llm.ollama import OllamaProvider
        return OllamaProvider(
            model_name=config.model_name,
            temperature=config.temperature
        )
    
    else:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            "Choose from: google, openai, anthropic, ollama"
        )
