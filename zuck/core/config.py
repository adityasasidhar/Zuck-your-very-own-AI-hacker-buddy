"""
Agent configuration using Pydantic for validation.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    """Configuration for the Zuck agent."""
    
    # Command execution settings
    max_commands: int = Field(default=50, gt=0, le=200)
    command_timeout: int = Field(default=60, gt=0, le=300)
    max_command_length: int = Field(default=1000, gt=0)
    
    # Allowed shell tools
    allowed_tools: List[str] = Field(
        default_factory=lambda: [
            'nmap', 'tcpdump', 'nc', 'netcat', 'host',
            'ls', 'cat', 'grep', 'find', 'ps', 'netstat', 'ss',
            'ip', 'ifconfig', 'ping', 'curl', 'wget',
            'echo', 'pwd', 'cd', 'mkdir', 'touch', 'head', 'tail',
            'awk', 'sed', 'sort', 'uniq', 'wc', 'chmod', 'chown'
        ]
    )
    
    # LLM Provider Configuration
    provider: str = Field(
        default="google", 
        description="LLM provider: google, openai, anthropic, ollama"
    )
    model_name: str = Field(
        default="gemini-2.5-flash", 
        description="Model name for the selected provider"
    )
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    
    # API Keys
    api_key_file: str = "apikey.txt"  # For Google API key
    openai_api_key: Optional[str] = Field(
        default=None, 
        description="OpenAI API key (or use OPENAI_API_KEY env var)"
    )
    anthropic_api_key: Optional[str] = Field(
        default=None, 
        description="Anthropic API key (or use ANTHROPIC_API_KEY env var)"
    )
    
    # Other settings
    log_directory: str = "logs"
    save_session_data: bool = True
