"""
CLI entry point with argument parsing.
"""

import argparse
import sys

from zuck.core.config import AgentConfig
from zuck.core.agent import ZuckAgent

# Default models per provider
DEFAULT_MODELS = {
    "google": "gemini-2.5-flash",
    "openai": "gpt-4",
    "anthropic": "claude-3-sonnet-20240229",
    "ollama": "llama3",
    "groq": "meta-llama/llama-4-scout-17b-16e-instruct",  # Llama 4, fast & good tools
}


def main():
    """Main entry point for the Zuck agent CLI."""
    # Get defaults from config (which reads .env)
    env_config = AgentConfig()
    
    parser = argparse.ArgumentParser(
        description="Zuck - AI Cybersecurity Agent for Linux Systems"
    )
    parser.add_argument(
        "--provider", 
        type=str, 
        default=env_config.provider,
        help="LLM provider (google, openai, anthropic, ollama, groq)"
    )
    parser.add_argument(
        "--model", 
        type=str, 
        default=None,
        help="Model name (default: depends on provider)"
    )
    parser.add_argument(
        "--temp", 
        type=float, 
        default=env_config.temperature,
        help="Temperature (0.0-2.0)"
    )
    parser.add_argument(
        "--max-commands", 
        type=int, 
        default=env_config.max_commands,
        help="Max commands per session"
    )
    
    args = parser.parse_args()
    
    # Use default model for provider if not specified
    model_name = args.model or DEFAULT_MODELS.get(args.provider, "")

    # Create configuration
    config = AgentConfig(
        provider=args.provider,
        model_name=model_name,
        temperature=args.temp,
        max_commands=args.max_commands
    )

    # Initialize and run agent
    try:
        agent = ZuckAgent(config)
        agent.run()
    except KeyboardInterrupt:
        print("\n\n⚠️ Session interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start agent: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
