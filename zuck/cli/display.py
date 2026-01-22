"""
Display utilities for the CLI using Rich.
"""

from typing import List, Any

from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table
from rich.theme import Theme

# Custom theme
zuck_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "red",
    "success": "green",
    "hacker": "red",
    "prompt": "dim white",
    "agent_name": "blue",
    "markdown.code": "cyan",
    "markdown.code_block": "white",
    "markdown.h1": "bold blue",
    "markdown.h2": "blue",
    "markdown.link": "dim cyan",
})

console = Console(theme=zuck_theme, highlight=False)


class Colors:
    """Legacy colors for compatibility."""
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"


class Display:
    """Handles CLI output and formatting using Rich."""

    @staticmethod
    def print_banner():
        """Print the welcome banner."""
        banner_text = """
    ███████╗██╗   ██╗ ██████╗██╗  ██╗
    ╚══███╔╝██║   ██║██╔════╝██║ ██╔╝
     ███╔╝  ██║   ██║██║     █████╔╝ 
    ███╔╝   ██║   ██║██║     ██╔═██╗ 
    ███████╗╚██████╔╝╚██████╗██║  ██╗
    ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
    AI Cybersecurity Agent | 55 Tools | v2.2
"""
        console.print(f"[hacker]{banner_text}[/hacker]")

    @staticmethod
    def print_session_info(session_id: str, model_name: str, tool_count: int):
        """Print session information."""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_row("[bold]Session:[/bold]", session_id)
        table.add_row("[bold]Model:[/bold]", model_name)
        table.add_row("[bold]Tools:[/bold]", f"{tool_count} loaded")
        
        console.print(table)
        console.print()

    @staticmethod
    def print_connecting():
        """Print connecting status."""
        console.print("⚡ [yellow]Initializing...[/yellow]")

    @staticmethod
    def print_ready():
        """Print ready message."""
        console.print("✓ [success]Ready[/success]\n")
        console.print("Type 'help' for commands, 'quit' to exit\n")

    @staticmethod
    def get_user_input() -> str:
        """Get input from the user."""
        # Local import to avoid circular dependency
        from zuck.cli.autocomplete import InputHandler
        
        if not hasattr(Display, '_input_handler'):
            Display._input_handler = InputHandler()
            
        try:
            # Using prompt_toolkit session
            from rich.console import Console
            c = Console()
            # Print the prompt manually with rich to keep styling consistent
            # c.print("[bold red]> [/bold red]", end="")
            # Actually prompt_toolkit handles the prompt better for cursor positioning
            return Display._input_handler.get_input([('class:prompt', '> ')])
        except (KeyboardInterrupt, EOFError):
            return "quit"

    @staticmethod
    def print_thinking():
        """Print thinking indicator."""
        console.print(" ... ", style="dim", end="")

    @staticmethod
    def print_response(message: str):
        """Print the agent's response with Markdown rendering."""
        console.print()
        
        # Simple clean header
        console.print("[bold magenta]Zuck[/bold magenta]")
        
        # Render markdown content
        md = Markdown(message, code_theme="manni")
        console.print(md)
        console.print()

    @staticmethod
    def print_plan(plan_output: str):
        """Print the plan prominently."""
        console.print()
        console.print(" [bold yellow]EXECUTION PLAN[/bold yellow]")
        console.print()
        
        # Render markdown content
        md = Markdown(plan_output, code_theme="manni")
        console.print(md)
        console.print()

    @staticmethod
    def print_error(message: str):
        """Print an error message."""
        console.print(f"\n ✗ [error]{message}[/error]")

    @staticmethod
    def print_tool_use(tool_name: str, input_data: dict, result: str):
        """Print tool usage info."""
        console.print(f"\n[dim]🔧 {tool_name}[/dim]")
        
        # Optionally show result if short
        if len(str(result)) < 200:
            console.print(f"[dim]✓ Result: {result}[/dim]")
        else:
            console.print(f"[dim]✓ Result: {str(result)[:100]}...[/dim]")

    @staticmethod
    def print_help():
        """Print help message."""
        help_text = """
# Available Commands

- `help`    : Show this help message
- `tools`   : List all available tools
- `clear`   : Clear the screen
- `quit`    : Exit the session

# Slash Commands (Quick Access)

- `/tools`     : Browse all tools by category
- `/models`    : Show available models per provider
- `/providers` : List supported LLM providers
- `/config`    : Show current configuration
- `/session`   : Show session statistics
- `/shell`     : Show shell session info
- `/help`      : Show slash command help

# Examples

- "Scan ports on google.com"
- "Plan a pentest for 192.168.1.10"
- "Generate a reverse shell payload"
- "Check recent CVEs for Nginx"
"""
        console.print(Markdown(help_text))

    @staticmethod
    def print_summary(session_summary: str, token_summary: str):
        """Print session summary."""
        console.print("\n[bold]─── Session Summary ───[/bold]")
        console.print(session_summary)
        console.print(token_summary)

    @staticmethod
    def print_tools_list(tools: List[Any]):
        """Print list of available tools."""
        table = Table(title="Available Tools")
        table.add_column("Tool Name", style="cyan")
        table.add_column("Description", style="white")
        
        for tool in tools:
            # Handle both function-based and class-based tools
            name = getattr(tool, 'name', str(tool))
            desc = getattr(tool, 'description', 'No description')
            # Truncate desc
            if len(desc) > 80:
                desc = desc[:77] + "..."
            table.add_row(name, desc)
            
        console.print(table)
