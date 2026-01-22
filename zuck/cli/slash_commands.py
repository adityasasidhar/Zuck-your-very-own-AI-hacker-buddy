"""
Slash command handler for interactive REPL.
"""

from rich.console import Console
from rich.table import Table

console = Console()


class SlashCommands:
    """Handle slash commands like /tools, /models, /providers."""
    
    def __init__(self, agent):
        self.agent = agent
        self.commands = {
            "/tools": self.show_tools,
            "/models": self.show_models,
            "/providers": self.show_providers,
            "/config": self.show_config,
            "/session": self.show_session,
            "/shell": self.show_shell_info,
            "/help": self.show_slash_help,
            "/history": self.show_history,
            "/plan": self.show_plan,
            "/logs": self.show_logs,
            "/scan": lambda: self.show_template("scan"),
            "/exploit": lambda: self.show_template("exploit"),
            "/recon": lambda: self.show_template("recon"),
        }
    
    def handle(self, command: str) -> bool:
        """
        Handle a slash command.
        
        Returns:
            True if command was handled, False otherwise
        """
        cmd = command.lower().strip()
        
        if cmd in self.commands:
            self.commands[cmd]()
            return True
        
        # Partial match
        matches = [c for c in self.commands.keys() if c.startswith(cmd)]
        if len(matches) == 1:
            self.commands[matches[0]]()
            return True
        elif len(matches) > 1:
            console.print(f"\n[yellow]Ambiguous command. Did you mean: {', '.join(matches)}?[/yellow]\n")
            return True
        
        return False
    
    def show_slash_help(self):
        """Show available slash commands."""
        table = Table(title="Slash Commands", show_header=True)
        table.add_column("Command", style="cyan", width=15)
        table.add_column("Description", style="white")
        
        table.add_row("/tools", "List all available tools")
        table.add_row("/models", "Show available models per provider")
        table.add_row("/providers", "List supported LLM providers")
        table.add_row("/config", "Show current configuration")
        table.add_row("/session", "Show session statistics")
        table.add_row("/shell", "Show shell session info")
        table.add_row("/help", "Show this help message")
        
        console.print()
        console.print(table)
        console.print()
    
    def show_tools(self):
        """List all available tools."""
        # Group tools by category
        shell_tools = [t for t in self.agent.tools if t.name.startswith("shell_")]
        osint_tools = [t for t in self.agent.tools if t.name in ["shodan_host_lookup", "shodan_search", "username_search", "email_osint"]]
        offensive_tools = [t for t in self.agent.tools if t.name in ["cve_lookup", "search_exploits", "exploit_info", "sqli_payloads"]]
        defensive_tools = [t for t in self.agent.tools if t.name in ["extract_iocs", "extract_iocs_from_file", "analyze_file_hashes"]]
        other_tools = [t for t in self.agent.tools if t not in shell_tools + osint_tools + offensive_tools + defensive_tools]
        
        table = Table(title=f"Available Tools ({len(self.agent.tools)} total)", show_header=True)
        table.add_column("Category", style="bold cyan", width=15)
        table.add_column("Tool", style="green")
        table.add_column("Description", style="white", max_width=50)
        
        for tool in shell_tools:
            desc = tool.description[:80] + "..." if len(tool.description) > 80 else tool.description
            table.add_row("SHELL", tool.name, desc)
        
        for tool in osint_tools:
            desc = tool.description[:80] + "..." if len(tool.description) > 80 else tool.description
            table.add_row("OSINT", tool.name, desc)
        
        for tool in offensive_tools:
            desc = tool.description[:80] + "..." if len(tool.description) > 80 else tool.description
            table.add_row("OFFENSIVE", tool.name, desc)
        
        for tool in defensive_tools:
            desc = tool.description[:80] + "..." if len(tool.description) > 80 else tool.description
            table.add_row("DEFENSIVE", tool.name, desc)
        
        for tool in other_tools:
            desc = tool.description[:80] + "..." if len(tool.description) > 80 else tool.description
            table.add_row("UTILITY", tool.name, desc)
        
        console.print()
        console.print(table)
        console.print()
    
    def show_models(self):
        """Show available models per provider."""
        table = Table(title="Available Models by Provider", show_header=True)
        table.add_column("Provider", style="bold cyan", width=12)
        table.add_column("Model", style="green")
        table.add_column("Notes", style="white")
        
        # Google Gemini
        table.add_row("google", "gemini-3-pro", "Most intelligent, SOTA reasoning (preview)")
        table.add_row("", "gemini-3-flash", "Fast with frontier intelligence (preview)")
        table.add_row("", "gemini-2.5-pro", "Chat optimized, experimental")
        table.add_row("", "gemini-2.5-flash", "Fast, multimodal (default)")
        table.add_row("", "gemini-2.5-flash-lite", "Lightweight version")
        
        # OpenAI
        table.add_row("openai", "gpt-5.2", "Most proficient model series")
        table.add_row("", "gpt-5-nano", "Fast writing and retrieval")
        table.add_row("", "gpt-5-mini", "Most accurate for complex tasks")
        
        # Anthropic Claude
        table.add_row("anthropic", "claude-4.5-opus", "Most intelligent, deep reasoning")
        table.add_row("", "claude-4.5-sonnet", "Balanced capability (recommended)")
        table.add_row("", "claude-4.5-haiku", "Fastest Claude model")
        
        # Groq
        table.add_row("groq", "compound", "AI system with web search & code execution")
        table.add_row("", "gpt-oss-120b", "OpenAI's open-weight, 500 tps (default)")
        table.add_row("", "gpt-oss-20b", "Smaller GPT-OSS, 1000 tps")
        table.add_row("", "llama-4-scout-17b-16e-instruct", "Fast, good tools")
        table.add_row("", "llama-4-maverick-17b-128e-instruct", "Enhanced version")
        table.add_row("", "llama-3.3-70b-versatile", "Classic Llama")
        table.add_row("", "kimi-k2-instruct", "MoE with 131K context")
        
        # Ollama
        table.add_row("ollama", "deepseek-r1", "Open reasoning model (latest)")
        table.add_row("", "llama3.1", "Meta's SOTA, 8B/70B/405B")
        table.add_row("", "llama3.3", "Similar to 3.1 405B performance, 70B")
        table.add_row("", "llama4", "Meta's multimodal, 16x17b/128x17b")
        table.add_row("", "gemma3", "Current most capable on single GPU")
        table.add_row("", "qwen3", "Latest Qwen with thinking")
        table.add_row("", "qwen2.5", "Multilingual, 18T tokens")
        table.add_row("", "phi4", "Microsoft 14B state-of-the-art")
        table.add_row("", "mistral", "7B updated to v0.3 (default)")
        table.add_row("", "codellama", "Code-focused, 20+ languages")
        table.add_row("", "qwen2.5-coder", "Latest code-specific")
        table.add_row("", "deepseek-v3.1", "671B MoE with thinking mode")
        table.add_row("", "llava", "Vision + language understanding")

        console.print()
        console.print(table)
        console.print("\n[dim]Usage: python -m zuck --provider <provider> --model <model>[/dim]\n")

    def show_providers(self):
        """List supported LLM providers."""
        table = Table(title="Supported Providers", show_header=True)
        table.add_column("Provider", style="bold cyan", width=12)
        table.add_column("Tool Support", style="green", width=15)
        table.add_column("API Key Required", style="yellow", width=18)
        table.add_column("Notes", style="white")
        
        table.add_row("google", "✓ Native", "GOOGLE_API_KEY", "Gemini 3/2.5 models, fast")
        table.add_row("openai", "✓ Native", "OPENAI_API_KEY", "GPT-5/4 models, reliable")
        table.add_row("anthropic", "✓ Native", "ANTHROPIC_API_KEY", "Claude 4.5/3.7 models, smart")
        table.add_row("groq", "✓ Native", "GROQ_API_KEY", "Fastest inference, supports open models")
        table.add_row("ollama", "⚠ Limited", "None", "Local privacy, DeepSeek/Llama models")
        
        console.print()
        console.print(table)
        console.print("\n[dim]Set API keys in .env file or environment variables[/dim]\n")
    
    def show_config(self):
        """Show current configuration."""
        config = self.agent.config
        
        table = Table(title="Current Configuration", show_header=False, box=None)
        table.add_column("Setting", style="cyan", width=25)
        table.add_column("Value", style="white")
        
        table.add_row("Provider", config.provider)
        table.add_row("Model", config.model_name)
        table.add_row("Temperature", str(config.temperature))
        table.add_row("Max Commands", str(config.max_commands))
        table.add_row("Command Timeout", f"{config.command_timeout}s")
        table.add_row("Max Command Length", str(config.max_command_length))
        table.add_row("Log Directory", config.log_directory)
        
        console.print()
        console.print(table)
        console.print()
    
    def show_session(self):
        """Show session statistics."""
        summary = self.agent.session.get_summary()
        token_summary = self.agent.token_tracker.get_summary()
        
        table = Table(title="Session Statistics", show_header=False, box=None)
        table.add_column("Metric", style="cyan", width=25)
        table.add_column("Value", style="white")
        
        table.add_row("Session ID", summary["session_id"])
        table.add_row("Duration", summary["duration"])
        table.add_row("Commands Executed", str(summary["successful"]))
        table.add_row("Commands Blocked", str(summary["blocked"]))
        table.add_row("Commands Failed", str(summary["failed"]))
        table.add_row("Success Rate", summary["success_rate"])
        table.add_row("", "")
        table.add_row("API Calls", str(token_summary["total_api_calls"]))
        table.add_row("Total Tokens", str(token_summary["total_tokens"]))
        table.add_row("Estimated Cost", token_summary["estimated_cost"])
        
        console.print()
        console.print(table)
        console.print()
    
    def show_shell_info(self):
        """Show shell session information."""
        from zuck.shell.tools import get_manager
        
        try:
            manager = get_manager()
            sessions = manager.list_sessions()
            bg_processes = manager.list_background()
            
            # Sessions table
            table = Table(title="Shell Sessions", show_header=True)
            table.add_column("ID", style="cyan")
            table.add_column("Default", style="green", width=10)
            table.add_column("Status", style="yellow", width=10)
            table.add_column("Commands", style="white", width=10)
            
            for session in sessions:
                is_default = "✓" if session["is_default"] else ""
                status = "alive" if session["is_alive"] else "dead"
                table.add_row(
                    session["id"],
                    is_default,
                    status,
                    str(session["command_count"])
                )
            
            console.print()
            console.print(table)
            
            # Background processes
            if bg_processes:
                bg_table = Table(title="Background Processes", show_header=True)
                bg_table.add_column("ID", style="cyan", width=10)
                bg_table.add_column("PID", style="yellow", width=8)
                bg_table.add_column("Status", style="green", width=10)
                bg_table.add_column("Command", style="white")
                
                for proc in bg_processes:
                    status = "running" if proc["is_running"] else "stopped"
                    cmd = proc["command"][:50] + "..." if len(proc["command"]) > 50 else proc["command"]
                    bg_table.add_row(proc["id"], proc["pid"], status, cmd)
                
                console.print()
                console.print(bg_table)
            
            console.print()
            
        except Exception as e:
            console.print(f"\n[red]Error getting shell info: {e}[/red]\n")

    def show_history(self):
        """Show command history."""
        history = self.agent.session.history
        if not history:
            console.print("\n[yellow]No history available yet.[/yellow]\n")
            return
            
        table = Table(title="Command History", show_header=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Command", style="white")
        
        for i, cmd in enumerate(history[-20:], 1):
            if hasattr(cmd, 'content'):
                content = cmd.content[:80] + "..." if len(cmd.content) > 80 else cmd.content
                table.add_row(str(i), content)
        
        console.print()
        console.print(table)
        console.print()

    def show_plan(self):
        """Show current plan."""
        # This assumes the plan is stored in the last tool result or agent state
        # For now, we'll try to get it from the agent tools if available
        console.print("\n[yellow]Plan viewing not yet fully implemented.[/yellow]\n")
        # In a real implementation we would fetch the plan state

    def show_logs(self):
        """Show recent logs."""
        import os
        log_file = os.path.join(self.agent.config.log_directory, f"{self.agent.session.session_id}.jsonl")
        
        if not os.path.exists(log_file):
             console.print("\n[yellow]No log file found.[/yellow]\n")
             return

        console.print(f"\n[bold]Latests Logs ({log_file}):[/bold]")
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:
                    console.print(line.strip(), style="dim")
        except Exception as e:
            console.print(f"[red]Error reading logs: {e}[/red]")
        console.print()

    def show_template(self, template_type: str):
        """Show a command template."""
        templates = {
            "scan": "Scan a target for open ports:\n> shell_run(\"nmap -sV -p- target.com\")",
            "exploit": "Search for exploits:\n> search_exploits(\"apache 2.4\")",
            "recon": "Recon workflow:\n1. shodan_host_lookup(\"ip\")\n2. shell_run(\"dig domain.com\")"
        }
        
        if template_type in templates:
            console.print(f"\n[bold cyan]Template ({template_type}):[/bold cyan]")
            console.print(templates[template_type])
            console.print()
