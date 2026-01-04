"""
Interactive REPL loop for the agent.
"""

import traceback
import logging
from typing import Optional

from zuck.core.session import SessionState
from zuck.cli.display import Display

logger = logging.getLogger('zuck_agent')


class REPL:
    """Interactive Read-Eval-Print Loop for the agent."""
    
    def __init__(self, agent):
        """
        Initialize the REPL.
        
        Args:
            agent: ZuckAgent instance
        """
        self.agent = agent
        self.session = agent.session
    
    def run(self):
        """Run the interactive REPL loop."""
        Display.print_header(self.session.session_id)
        
        # Initial greeting
        try:
            Display.print_connecting()
            initial_response = self.agent.initialize()
            Display.print_ready(initial_response)
        except Exception as e:
            Display.print_error(f"Initialization failed: {e}")
            return

        # Main loop
        while self.session.is_active:
            try:
                user_input = Display.get_user_input()

                if not user_input:
                    continue

                if user_input.lower() in ['quit', 'exit', 'bye']:
                    self.session.complete()
                    break

                self._process_input(user_input)

            except KeyboardInterrupt:
                print("\n\n⚠️ Session interrupted by user.")
                self.session.complete()
                break
            except Exception as e:
                logger.critical(f"Critical error: {e}")
                traceback.print_exc()
                break

        # Print session summary
        self._print_summary()
    
    def _process_input(self, user_input: str):
        """Process user input and generate response."""
        Display.print_thinking()
        response_text = self.agent.send_message(user_input)

        if not response_text:
            Display.print_error("Failed to get response from AI.")
            return

        try:
            # Try to parse as JSON command proposal
            proposal = self.agent.proposal_handler.parse_response(response_text)
            
            if proposal:
                # If there's a message to the user in the JSON, print it
                if proposal.message_to_user:
                    Display.print_response(proposal.message_to_user)
                
                # If there's a plan, print it
                if proposal.plan:
                    Display.print_plan(proposal.plan)

                result = self.agent.proposal_handler.process(proposal)

                if result:
                    self.session.add_result(result)

                    # Feed result back to AI
                    if result.command.startswith("tool:"):
                        result_message = f"Tool execution result:\n{result.output}"
                    else:
                        result_message = f"Command execution result:\nStatus: {result.status}\nOutput:\n{result.output}"
                        
                    print("\n🤖 Analyzing result...")
                    self.agent.send_message(result_message)
            else:
                # If not valid JSON, just print the text (conversational response)
                Display.print_response(response_text)
                
        except Exception as e:
            logger.error(f"Error in REPL loop: {e}")
            Display.print_error(f"An error occurred: {e}")
    
    def _print_summary(self):
        """Print session summary."""
        summary = self.session.get_summary()
        token_summary = self.agent.token_tracker.get_summary()
        Display.print_summary(summary, token_summary)
