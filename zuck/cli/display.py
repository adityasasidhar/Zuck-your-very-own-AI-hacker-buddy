"""
Console display utilities.
"""

from typing import Dict, Any


class Display:
    """Console display utilities for the REPL."""
    
    # Emoji constants
    ROBOT = "🤖"
    USER = "👤"
    TOOL = "🔧"
    SUCCESS = "✅"
    ERROR = "❌"
    WARNING = "⚠️"
    QUESTION = "❓"
    STOP = "🛑"
    PLAN = "📋"
    COMMAND = "💻"
    LOCK = "🔒"
    THINK = "🤔"
    
    @classmethod
    def print_header(cls, session_id: str):
        """Print session header."""
        print(f"Zuck Agent initialized (Session: {session_id})")
        print("Type 'quit', 'exit', or 'bye' to end the session.")
    
    @classmethod
    def print_connecting(cls):
        """Print connecting message."""
        print(f"\n{cls.ROBOT} Connecting to AI model...")
    
    @classmethod
    def print_ready(cls, message: str):
        """Print ready message."""
        print(f"{cls.SUCCESS} {message}")
    
    @classmethod
    def print_thinking(cls):
        """Print thinking message."""
        print(f"{cls.ROBOT} Zuck is thinking...")
    
    @classmethod
    def print_response(cls, message: str):
        """Print agent response."""
        print(f"\n{cls.ROBOT} Zuck: {message}")
    
    @classmethod
    def print_plan(cls, plan: str):
        """Print plan."""
        print(f"{cls.PLAN} Plan: {plan}")
    
    @classmethod
    def print_tool_use(cls, tool_name: str):
        """Print tool use."""
        print(f"\n{cls.TOOL} Using tool: {tool_name}")
    
    @classmethod
    def print_tool_result(cls, result: str, success: bool = True):
        """Print tool result."""
        if success:
            print(f"✓ Result: {result[:200]}...")
        else:
            print(f"✗ Error: {result}")
    
    @classmethod
    def print_error(cls, message: str):
        """Print error message."""
        print(f"{cls.ERROR} {message}")
    
    @classmethod
    def print_summary(cls, summary: Dict[str, Any], token_summary: Dict[str, Any]):
        """Print session summary."""
        print("\n" + "=" * 40)
        print("Session Summary")
        print("=" * 40)
        print(f"Duration: {summary['duration']}")
        print(f"Commands: {summary['total_commands']} (Success: {summary['successful']}, Failed: {summary['failed']})")
        print(f"Tokens: {token_summary['total_tokens']} (Cost: {token_summary['estimated_cost']})")
        print("=" * 40)
    
    @classmethod
    def get_user_input(cls) -> str:
        """Get user input."""
        return input(f"\n{cls.USER} You: ").strip()
