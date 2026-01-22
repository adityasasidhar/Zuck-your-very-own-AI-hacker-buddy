"""
Proposal parsing and handling.
"""

import re
import json
import logging
from typing import Optional, List, Any

from zuck.core.models import (
    CommandProposal, 
    CommandResult, 
    CommandStatus,
    AgentAction, 
    SecurityLevel
)
from zuck.core.config import AgentConfig
from zuck.security.validator import CommandValidator
from zuck.execution.executor import CommandExecutor
from zuck.utils.tracking import PerformanceMetrics

logger = logging.getLogger('zuck_agent')


class ProposalHandler:
    """Handles parsing and processing of LLM proposals."""
    
    def __init__(
        self, 
        config: AgentConfig, 
        metrics: PerformanceMetrics,
        tools: List[Any]
    ):
        self.config = config
        self.validator = CommandValidator(config)
        self.executor = CommandExecutor(config, metrics)
        self.tools = tools
    
    def parse_response(self, response_text: str) -> Optional[CommandProposal]:
        """
        Parse LLM response text into a CommandProposal.
        
        Args:
            response_text: Raw text from the LLM
            
        Returns:
            CommandProposal or None if parsing fails
        """
        try:
            if not response_text:
                return None

            # Clean up response (remove markdown code blocks if present)
            cleaned_text = re.sub(
                r'```(?:json)?\s*(.*?)\s*```', 
                r'\1', 
                response_text.strip(), 
                flags=re.DOTALL
            )
            
            # If no code blocks were found, try to find JSON structure
            if cleaned_text == response_text.strip():
                start_idx = response_text.find('{')
                end_idx = response_text.rfind('}')
                if start_idx != -1 and end_idx != -1:
                    cleaned_text = response_text[start_idx:end_idx+1]

            data = json.loads(cleaned_text)
            return CommandProposal(**data)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return None
        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            return None
    
    def process(self, proposal: CommandProposal) -> Optional[CommandResult]:
        """
        Process a command proposal.
        
        Args:
            proposal: The proposal to process
            
        Returns:
            CommandResult or None
        """
        logger.debug(f"Processing proposal: {proposal.action}")

        if proposal.action == AgentAction.COMPLETE:
            logger.info(f"Task completed: {proposal.message_to_user}")
            print(f"\n✅ Task Completed: {proposal.message_to_user}")
            return None

        elif proposal.action == AgentAction.ABORT:
            logger.warning(f"Task aborted: {proposal.message_to_user}")
            print(f"\n Task Aborted: {proposal.message_to_user}")
            return None

        elif proposal.action == AgentAction.REQUEST_CLARIFICATION:
            logger.info(f"Clarification requested: {proposal.message_to_user}")
            print(f"\n❓ Clarification Needed: {proposal.message_to_user}")
            return None
            
        elif proposal.action == AgentAction.USE_TOOL:
            return self._handle_tool_use(proposal)

        elif proposal.action == AgentAction.EXECUTE_COMMAND:
            return self._handle_command(proposal)

        return None
    
    def _handle_tool_use(self, proposal: CommandProposal) -> Optional[CommandResult]:
        """Handle tool use action from JSON proposal."""
        tool_name = proposal.tool_name
        tool_input = proposal.tool_input or {}
        
        logger.info(f"Executing tool from JSON: {tool_name}")
        print(f"\n🔧 Using tool: {tool_name}")
        
        # Find and execute tool
        for tool in self.tools:
            if tool.name == tool_name:
                try:
                    result = tool.invoke(tool_input)
                    print(f"✓ Result: {str(result)[:200]}...")
                    
                    return CommandResult(
                        command=f"tool:{tool_name}",
                        status=CommandStatus.SUCCESS,
                        output=str(result),
                        execution_time=0
                    )
                except Exception as e:
                    print(f"✗ Error: {str(e)}")
                    return CommandResult(
                        command=f"tool:{tool_name}",
                        status=CommandStatus.ERROR,
                        output=str(e),
                        execution_time=0
                    )
        
        print(f"✗ Error: Tool {tool_name} not found")
        return None
    
    def _handle_command(self, proposal: CommandProposal) -> Optional[CommandResult]:
        """Handle command execution action (no confirmation required)."""
        logger.info(f"Executing command: {proposal.command}")
        
        # Validate command (for logging only now)
        is_valid, error_msg, risk_level = self.validator.validate(proposal)

        if not is_valid:
            logger.warning(f"Command validation issue: {error_msg}")
            return CommandResult(
                command=proposal.command,
                status=CommandStatus.BLOCKED,
                output=f"Validation issue: {error_msg}",
                execution_time=0,
                blocked_reason=error_msg,
                security_level=risk_level
            )

        # Execute command directly (no confirmation)
        return self.executor.execute(proposal)
