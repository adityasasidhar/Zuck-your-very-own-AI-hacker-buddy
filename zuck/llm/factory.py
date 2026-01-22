"""
Factory for creating LangChain Chat Models.
"""

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zuck.core.config import AgentConfig

logger = logging.getLogger('zuck_agent')


def create_provider(config: "AgentConfig") -> Any:
    """
    Factory method to create the appropriate LangChain Chat Model based on configuration.
    
    Args:
        config: AgentConfig with provider settings
        
    Returns:
        Configured LangChain Chat Model instance (e.g. ChatOpenAI, ChatGoogleGenerativeAI)
        
    Raises:
        ValueError: If provider is not supported
    """
    provider = config.provider.lower()
    
    logger.info(f"Creating LLM provider: {provider}")
    
    if provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        
        if not config.google_api_key:
             raise ValueError("GOOGLE_API_KEY not set")

        return ChatGoogleGenerativeAI(
            model=config.model_name or "gemini-2.5-flash-lite",
            temperature=1.0,
            google_api_key=config.google_api_key,
            thinking=True,
            max_tokens=None,
            max_retries=3,
        )
    
    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        
        if not config.openai_api_key:
            raise ValueError("OPENAI_API_KEY not set")

        return ChatOpenAI(
            model=config.model_name or "gpt-5",
            temperature=config.temperature,
            api_key=config.openai_api_key,
        )
    
    elif provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        
        if not config.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        return ChatAnthropic(
            model=config.model_name or "claude-3-sonnet-20240229",
            temperature=config.temperature,
            api_key=config.anthropic_api_key,
        )
    
    elif provider == "ollama":
        from langchain_ollama import ChatOllama
        
        base_url = config.ollama_base_url or "http://localhost:11434"
        return ChatOllama(
            model=config.model_name or "llama3",
            temperature=config.temperature,
            base_url=base_url
        )
    
    elif provider == "groq":
        from langchain_groq import ChatGroq
        
        if not config.groq_api_key:
            raise ValueError("GROQ_API_KEY not set")
            
        return ChatGroq(
            model=config.model_name or "llama-3.3-70b-versatile",
            temperature=config.temperature,
            api_key=config.groq_api_key
        )
    
    else:
        raise ValueError(
            f"Unsupported provider: {provider}. "
            "Choose from: google, openai, anthropic, ollama, groq"
        )
