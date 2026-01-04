"""
Interactive REPL loop for the agent.
"""

import os
import json
import traceback
import logging

from zuck.cli.display import Display, Colors

logger = logging.getLogger('zuck_agent')


class REPL:
    """Interactive Read-Eval-Print Loop for the agent."""
    
    def __init__(self, agent):
        """Initialize the REPL."""
        self.agent = agent
        self.session = agent.session
    
    def run(self):
        """Run the interactive REPL loop."""
        # Clear screen and show banner
        os.system('clear' if os.name != 'nt' else 'cls')
        Display.print_banner()
        Display.print_session_info(
            self.session.session_id,
            self.agent.config.model_name,
            len(self.agent.tools)
        )
        
        # Initialize
        try:
            Display.print_connecting()
            self.agent.initialize()
            Display.print_ready()
        except Exception as e:
            Display.print_error(f"Initialization failed: {e}")
            return

        # Main loop
        while self.session.is_active:
            try:
                user_input = Display.get_user_input()

                if not user_input:
                    continue

                # Handle special commands
                if user_input.lower() in ['quit', 'exit', 'bye', 'q']:
                    print(f"\n{Colors.CYAN}Later, hacker. Stay safe. 👋{Colors.RESET}\n")
                    self.session.complete()
                    break
                
                if user_input.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    Display.print_banner()
                    continue
                
                if user_input.lower() == 'help':
                    Display.print_help()
                    continue
                
                if user_input.lower() == 'tools':
                    Display.print_tools_list(self.agent.tools)
                    continue

                # Process with ReAct agent
                Display.print_thinking()
                response = self.agent.send_message(user_input)
                
                if response:
                    Display.print_response(response)
                else:
                    Display.print_error("No response from agent")

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Interrupted. Type 'quit', 'exit', 'bye', 'q' to exit.{Colors.RESET}")
                continue
            except Exception as e:
                logger.critical(f"Critical error: {e}")
                Display.print_error(str(e))
                traceback.print_exc()
                break

        # Print session summary
        self._print_summary()
    
    def _print_summary(self):
        """Print session summary."""
        summary = self.session.get_summary()
        token_summary = self.agent.token_tracker.get_summary()
        Display.print_summary(summary, token_summary)
