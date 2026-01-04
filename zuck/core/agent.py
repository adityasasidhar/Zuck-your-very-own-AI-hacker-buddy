"""
Main ZuckAgent class - orchestrates all components.
"""

import json
import time
import logging
import traceback
from datetime import datetime
from typing import List, Optional, Union

from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

from zuck.core.config import AgentConfig
from zuck.core.models import TokenUsage
from zuck.core.session import SessionState
from zuck.llm import create_provider
from zuck.tools import get_all_tools
from zuck.execution import ProposalHandler
from zuck.utils import setup_logging, SystemInfo
from zuck.utils.tracking import TokenTracker, PerformanceMetrics

logger = logging.getLogger('zuck_agent')


class ZuckAgent:
    """
    Main agent class that orchestrates LLM, tools, and command execution.
    
    This is a clean orchestrator that delegates to specialized components:
    - LLM provider for model communication
    - Tool registry for available tools
    - Proposal handler for processing responses
    - Session state for tracking
    """
    
    SYSTEM_PROMPT = """You are Zuck, an expert cybersecurity assistant for Linux systems.

You have access to powerful tools for analysis and research. Use them when appropriate:

AVAILABLE TOOLS:
1. calculator - Network calculations (subnet size, IP ranges, hex/decimal conversions)
2. virustotal_lookup - Check file hashes, URLs, domains, IPs for malware
3. datetime_tool - Parse timestamps, analyze log times, calculate time differences
4. memory_store - Store and retrieve findings during the session
5. read_file - Read configuration files and logs safely
6. http_request - Make HTTP requests to test APIs and check headers
7. dns_lookup - Query DNS records (A, MX, TXT, NS, etc.)
8. whois_lookup - Get domain registration information
9. python_repl - Execute Python code for data analysis
10. wikipedia_search - Look up security concepts and protocols

When the LLM supports tool calling, you can call tools directly. Otherwise, your responses MUST be valid JSON matching this exact schema:

{
  "action": "execute_command" | "use_tool" | "request_clarification" | "complete" | "abort",
  "plan": "Brief description of what you're doing (10-500 chars)",
  "command": "exact command to run (only if action is execute_command)",
  "tool_name": "name of tool to use (only if action is use_tool)",
  "tool_input": {"arg1": "value1", "arg2": "value2"} (only if action is use_tool),
  "requires_sudo": true | false,
  "expected_output": "what output you expect",
  "reasoning": "why this action is safe and necessary",
  "message_to_user": "message for user (for clarification/complete/abort actions)"
}

CRITICAL RULES:
1. Output ONLY valid JSON, no markdown, no explanation outside JSON
2. Propose ONE action at a time (either command OR tool, not both)
3. NEVER suggest destructive commands (rm -rf /, mkfs, dd to devices, etc.)
4. Use tools when they're more appropriate than shell commands
5. Use only installed tools: nmap, whois, tcpdump, tshark, netcat, dig, nslookup, aircrack-ng
6. If task is complete, use action "complete" with message_to_user
7. If you cannot proceed safely, use action "abort" with explanation
8. Always provide clear reasoning for security-sensitive commands

TOOL USAGE EXAMPLES:
- To check subnet size: use calculator with "192.168.1.0/24 size"
- To check domain reputation: use virustotal_lookup with domain name
- To look up DNS: use dns_lookup instead of dig command
- To research a concept: use wikipedia_search

Be concise, security-focused, and always output valid JSON."""

    def __init__(self, config: AgentConfig):
        """
        Initialize the Zuck agent.
        
        Args:
            config: Agent configuration
        """
        self.config = config
        self.session = SessionState()

        # Setup logging
        global logger
        logger = setup_logging(self.session.session_id, config.log_directory)

        logger.info("=" * 80)
        logger.info("Initializing Zuck Agent")
        logger.info(f"Session ID: {self.session.session_id}")
        logger.info("=" * 80)

        # Initialize LLM provider
        self.provider = create_provider(config)
        self.chat_history: List[Union[SystemMessage, HumanMessage, AIMessage]] = []

        # Initialize tools
        self.tools = get_all_tools()
        logger.info(f"Initialized {len(self.tools)} tools")
        
        # Bind tools to provider
        try:
            self.provider.bind_tools(self.tools)
            logger.info("Tools bound to LLM provider")
        except Exception as e:
            logger.warning(f"Could not bind tools: {e}")

        # Initialize tracking
        self.token_tracker = TokenTracker(session_id=self.session.session_id)
        self.metrics = PerformanceMetrics(session_id=self.session.session_id)

        # Initialize proposal handler
        self.proposal_handler = ProposalHandler(config, self.metrics, self.tools)

        # Gather system info
        self.system_info = SystemInfo.gather(config.allowed_tools)

        logger.info(f"Configuration: {config.model_dump_json()}")

    def initialize(self) -> str:
        """
        Initialize the chat session.
        
        Returns:
            Initialization status message
        """
        try:
            logger.info("Initializing chat session...")

            # Create system message with context
            context_message = f"""{self.SYSTEM_PROMPT}

System Information:
{self.system_info.model_dump_json(indent=2)}

Respond with JSON only."""

            # Initialize chat history with system message
            self.chat_history = [SystemMessage(content=context_message)]
            
            # Gemini requires at least one HumanMessage
            initial_message = "I understand. I'm ready to assist with cybersecurity tasks. I will respond only with valid JSON."
            self.chat_history.append(HumanMessage(content=initial_message))

            # Send initial message to warm up the model
            start_time = datetime.now()
            response = self.provider.invoke(self.chat_history)
            api_time = (datetime.now() - start_time).total_seconds()

            self.metrics.add_api_time(api_time)

            # Track token usage
            self._track_token_usage(response)
            
            # Add response to history
            self.chat_history.append(AIMessage(content=response.content))

            logger.info(f"Chat initialized successfully in {api_time:.3f}s")
            logger.info(f"Model: {self.config.model_name}, Temperature: {self.config.temperature}")
            logger.info(f"Provider: {self.config.provider}")

            return "Zuck agent initialized and ready."

        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            logger.debug(traceback.format_exc())
            raise

    def _track_token_usage(self, response):
        """Track token usage from provider response."""
        try:
            if response.usage_metadata:
                usage = TokenUsage(
                    prompt_tokens=response.usage_metadata.get('prompt_tokens', 0),
                    completion_tokens=response.usage_metadata.get('completion_tokens', 0),
                    total_tokens=response.usage_metadata.get('total_tokens', 0),
                    model=self.config.model_name
                )
                self.token_tracker.add_usage(usage)
        except Exception as e:
            logger.warning(f"Failed to track token usage: {e}")

    def send_message(self, message: str) -> Optional[str]:
        """
        Send a message to the LLM.
        
        Args:
            message: User message to send
            
        Returns:
            LLM response text or None on error
        """
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries + 1):
            try:
                logger.debug(f"Sending message (length: {len(message)})")

                # Add user message to history
                self.chat_history.append(HumanMessage(content=message))

                start_time = datetime.now()
                response = self.provider.invoke(self.chat_history)
                api_time = (datetime.now() - start_time).total_seconds()

                self.metrics.add_api_time(api_time)
                self._track_token_usage(response)

                # Handle tool calls if present
                if response.tool_calls:
                    tool_results = self._handle_tool_calls(response.tool_calls)
                    if tool_results:
                        # Invoke model again with tool results
                        logger.info("Tool calls processed, getting final response")
                        
                        start_time = datetime.now()
                        response = self.provider.invoke(self.chat_history)
                        api_time = (datetime.now() - start_time).total_seconds()
                        
                        self.metrics.add_api_time(api_time)
                        self._track_token_usage(response)

                # Add AI response to history
                self.chat_history.append(AIMessage(content=response.content))

                logger.debug(f"Received response in {api_time:.3f}s (length: {len(response.content)})")

                return response.content

            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str or "rate_limit" in error_str.lower():
                    if attempt < max_retries:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"API quota exceeded (429). Retrying in {delay}s... (Attempt {attempt + 1}/{max_retries})")
                        print(f"\n⏳ API quota exceeded. Retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    else:
                        logger.error("Max retries exceeded for API quota error")
                        print("\n❌ Max retries exceeded. Please check your API quota.")
                
                logger.error(f"Failed to send message: {e}")
                logger.debug(traceback.format_exc())
                return None

    def _handle_tool_calls(self, tool_calls: List) -> Optional[str]:
        """
        Handle tool calls from LLM response.
        
        Args:
            tool_calls: List of tool call dicts
            
        Returns:
            Formatted tool results or None
        """
        if not tool_calls:
            return None
        
        logger.info(f"Processing {len(tool_calls)} tool call(s)")
        tool_results = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get('name')
            tool_input = tool_call.get('args', {})
            tool_id = tool_call.get('id', 'unknown')
            
            logger.info(f"Executing tool: {tool_name} with input: {tool_input}")
            print(f"\n🔧 Using tool: {tool_name}")
            
            # Find and execute the tool
            tool_found = False
            for tool in self.tools:
                if tool.name == tool_name:
                    try:
                        result = tool.invoke(tool_input)
                        tool_results.append({
                            "tool": tool_name,
                            "input": tool_input,
                            "result": result
                        })
                        
                        # Add tool message to chat history
                        self.chat_history.append(ToolMessage(
                            content=str(result),
                            tool_call_id=tool_id
                        ))
                        
                        logger.info(f"Tool {tool_name} executed successfully")
                        print(f"✓ Result: {str(result)[:200]}...")
                        tool_found = True
                        break
                    except Exception as e:
                        error_msg = f"Error executing tool {tool_name}: {str(e)}"
                        logger.error(error_msg)
                        tool_results.append({
                            "tool": tool_name,
                            "input": tool_input,
                            "error": str(e)
                        })
                        print(f"✗ Error: {str(e)}")
                        tool_found = True
                        break
            
            if not tool_found:
                logger.warning(f"Tool not found: {tool_name}")
                tool_results.append({
                    "tool": tool_name,
                    "error": "Tool not found"
                })
        
        if tool_results:
            return json.dumps(tool_results, indent=2)
        
        return None

    def run(self):
        """Run the interactive agent."""
        from zuck.cli.repl import REPL
        repl = REPL(self)
        repl.run()
