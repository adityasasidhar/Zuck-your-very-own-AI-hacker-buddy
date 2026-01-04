"""
CLI entry point with argument parsing.
"""

import argparse
import sys

from zuck.core.config import AgentConfig
from zuck.core.agent import ZuckAgent


def main():
    """Main entry point for the Zuck agent CLI."""
    parser = argparse.ArgumentParser(
        description="Zuck - AI Cybersecurity Agent for Linux Systems"
    )
    parser.add_argument(
        "--provider", 
        type=str, 
        default="google",
        help="LLM provider (google, openai, anthropic, ollama)"
    )
    parser.add_argument(
        "--model", 
        type=str, 
        default="gemini-2.5-flash",
        help="Model name"
    )
    parser.add_argument(
        "--temp", 
        type=float, 
        default=0.3,
        help="Temperature (0.0-2.0)"
    )
    parser.add_argument(
        "--max-commands", 
        type=int, 
        default=50,
        help="Max commands per session"
    )
    
    args = parser.parse_args()

    # Create configuration
    config = AgentConfig(
        provider=args.provider,
        model_name=args.model,
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
