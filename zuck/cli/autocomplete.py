"""
Autocomplete handler using prompt_toolkit.
"""

from typing import List
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style

class SlashCommandCompleter(Completer):
    """Completer for slash commands."""
    
    def __init__(self, commands: List[str]):
        # Store commands with descriptions
        self.commands = {
            "/tools": "Browse all available tools",
            "/models": "Show available models & capabilities",
            "/providers": "List supported LLM providers",
            "/config": "Show current configuration",
            "/session": "Show session statistics & cost",
            "/shell": "Show shell sessions & background jobs",
            "/history": "View command history",
            "/plan": "View current execution plan",
            "/logs": "Show recent log entries",
            "/help": "Show detailed help message",
            "/clear": "Clear the terminal screen",
            "/quit": "Exit the session",
            "/exit": "Exit the session",
            "/bye": "Exit the session",
            
            # Quick Templates
            "/scan": "Template: Scan a target",
            "/exploit": "Template: Search for exploits",
            "/recon": "Template: Reconnaissance workflow",
        }
    
    def get_completions(self, document, complete_event):
        """Get completions for the current input."""
        text = document.text_before_cursor
        
        # Only complete if we start with /
        if not text.startswith('/'):
            return
            
        for cmd, desc in self.commands.items():
            if cmd.startswith(text):
                yield Completion(
                    cmd,
                    start_position=-len(text),
                    display=cmd,
                    display_meta=desc
                )

class InputHandler:
    """Handles user input with rich features."""
    
    def __init__(self):
        self.style = Style.from_dict({
            'completion-menu.completion': 'bg:#008888 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'scrollbar.background': 'bg:#88aaaa',
            'scrollbar.button': 'bg:#222222',
        })
        
        self.completer = SlashCommandCompleter([])
        self.session = PromptSession(
            completer=self.completer,
            style=self.style,
            complete_while_typing=True
        )
    
    def get_input(self, prompt_text: str = "> ") -> str:
        """Get input from the user with autocomplete."""
        try:
            return self.session.prompt(prompt_text)
        except (KeyboardInterrupt, EOFError):
            return "quit"
