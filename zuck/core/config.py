"""
Agent configuration using .env file.
"""

import os
from typing import Optional, List

from dotenv import load_dotenv
from pydantic import BaseModel

# Load .env file
load_dotenv()


class AgentConfig(BaseModel):
    """Configuration for the Zuck agent."""
    
    # LLM settings
    provider: str = os.getenv("ZUCK_PROVIDER", "groq")
    model_name: str = os.getenv("ZUCK_MODEL", "")
    temperature: float = float(os.getenv("ZUCK_TEMPERATURE", "1.0"))
    
    # API Keys (from environment)
    google_api_key: Optional[str] = os.getenv("GOOGLE_API_KEY")
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    groq_api_key: Optional[str] = os.getenv("GROQ_API_KEY")
    
    # Tool API keys
    shodan_api_key: Optional[str] = os.getenv("SHODAN_API_KEY")
    virustotal_api_key: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    
    # Runtime settings
    max_commands: int = 50
    command_timeout: int = 60
    max_command_length: int = 1000
    
    # Allowed shell tools
    allowed_tools: List[str] = [
        "nmap", "tcpdump", "nc", "netcat", "host", "ls", "cat", "grep",
        "find", "ps", "netstat", "ss", "ip", "ifconfig", "ping", "curl",
        "wget", "echo", "pwd", "cd", "mkdir", "touch", "head", "tail",
        "awk", "sed", "sort", "uniq", "wc", "chmod", "chown", "dig",
        "nslookup", "traceroute", "mtr"
    ]
    
    # Logging
    log_directory: str = "logs"
    save_session_data: bool = True
