import os
import json
import time
import logging
import traceback
from datetime import datetime
from typing import List, Optional, Union, Dict, Any
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, ToolMessage

from models import (
    CommandProposal, CommandResult, CommandStatus, AgentAction, 
    SecurityLevel, SessionState, TokenUsage
)
from config import AgentConfig
from logger import setup_logging
from tracking import TokenTracker, PerformanceMetrics
from system import SystemInfo
from security import CommandValidator
from execution import CommandExecutor
from tools import get_all_tools

logger = logging.getLogger('zuck_agent')

class ZuckAgent:
    SYSTEM_PROMPT = """You are Zuck, an expert cybersecurity assistant for Pop!_OS Linux systems.

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
        self.config = config
        self.session = SessionState()

        # Setup logging
        global logger
        logger = setup_logging(self.session.session_id, config.log_directory)

        logger.info("=" * 80)
        logger.info("Initializing Zuck Agent")
        logger.info(f"Session ID: {self.session.session_id}")
        logger.info("=" * 80)

        # Initialize LangChain chat model
        self.chat_model = self._create_chat_model()
        self.chat_history: List[Union[SystemMessage, HumanMessage, AIMessage]] = []

        # Initialize tools
        self.tools = get_all_tools()
        logger.info(f"Initialized {len(self.tools)} tools")
        
        # Bind tools to chat model (if supported by provider)
        try:
            self.chat_model = self.chat_model.bind_tools(self.tools)
            logger.info("Tools bound to chat model")
        except AttributeError:
            logger.warning("Provider does not support tool binding, tools will be called manually")

        self.token_tracker = TokenTracker(session_id=self.session.session_id)
        self.metrics = PerformanceMetrics(session_id=self.session.session_id)

        self.validator = CommandValidator(config)
        self.executor = CommandExecutor(config, self.metrics)
        self.system_info = SystemInfo.gather(config.allowed_tools)

        logger.info(f"Configuration: {config.model_dump_json()}")

    def _create_chat_model(self):
        """Factory method to create the appropriate LangChain chat model based on provider"""
        provider = self.config.provider.lower()
        
        logger.info(f"Creating chat model for provider: {provider}")
        
        try:
            if provider == "google":
                # Load Google API key
                api_key = self._load_google_api_key()
                model = ChatGoogleGenerativeAI(
                    model=self.config.model_name,
                    google_api_key=api_key,
                    temperature=self.config.temperature,
                    convert_system_message_to_human=True  # Gemini compatibility
                )
                logger.info(f"Initialized Google Gemini: {self.config.model_name}")
                
            elif provider == "openai":
                # Use provided key or environment variable
                api_key = self.config.openai_api_key or os.getenv("OPENAI_API_KEY")
                if not api_key:
                    raise ValueError("OpenAI API key not found. Set openai_api_key in config or OPENAI_API_KEY env var")
                
                model = ChatOpenAI(
                    model=self.config.model_name,
                    api_key=api_key,
                    temperature=self.config.temperature,
                    model_kwargs={"response_format": {"type": "json_object"}}  # JSON mode
                )
                logger.info(f"Initialized OpenAI: {self.config.model_name}")
                
            elif provider == "anthropic":
                # Use provided key or environment variable
                api_key = self.config.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
                if not api_key:
                    raise ValueError("Anthropic API key not found. Set anthropic_api_key in config or ANTHROPIC_API_KEY env var")
                
                model = ChatAnthropic(
                    model=self.config.model_name,
                    api_key=api_key,
                    temperature=self.config.temperature
                )
                logger.info(f"Initialized Anthropic Claude: {self.config.model_name}")
                
            elif provider == "ollama":
                # Ollama runs locally, no API key needed
                from langchain_community.chat_models import ChatOllama
                model = ChatOllama(
                    model=self.config.model_name,
                    temperature=self.config.temperature,
                    format="json"  # Request JSON output
                )
                logger.info(f"Initialized Ollama: {self.config.model_name}")
                
            else:
                raise ValueError(f"Unsupported provider: {provider}. Choose from: google, openai, anthropic, ollama")
            
            return model
            
        except Exception as e:
            logger.critical(f"Failed to create chat model: {e}")
            raise

    def _load_google_api_key(self) -> str:
        """Load Google API key from file"""
        try:
            api_path = Path(self.config.api_key_file)
            if not api_path.exists():
                logger.critical(f"API key file not found: {self.config.api_key_file}")
                raise FileNotFoundError(f"API key file not found: {self.config.api_key_file}")

            key = api_path.read_text().strip()
            if not key:
                logger.critical("API key file is empty")
                raise ValueError("API key file is empty")

            logger.info("Google API key loaded successfully")
            return key
        except Exception as e:
            logger.critical(f"Failed to load API key: {e}")
            raise

    def initialize(self) -> str:
        try:
            logger.info("Initializing chat session...")

            # Create system message with context
            context_message = f"""{self.SYSTEM_PROMPT}

System Information:
{self.system_info.model_dump_json(indent=2)}

Respond with JSON only."""

            # Initialize chat history with system message
            self.chat_history = [SystemMessage(content=context_message)]
            
            # Gemini requires at least one HumanMessage, so we send an initial greeting
            # and add it to history for future context
            initial_message = "I understand. I'm ready to assist with cybersecurity tasks. I will respond only with valid JSON."
            self.chat_history.append(HumanMessage(content=initial_message))

            # Send initial message to warm up the model
            start_time = datetime.now()
            response = self.chat_model.invoke(self.chat_history)
            api_time = (datetime.now() - start_time).total_seconds()

            self.metrics.add_api_time(api_time)

            # Track token usage from LangChain response
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
        """Extract and track token usage from LangChain response"""
        try:
            # LangChain stores usage metadata in response_metadata
            if hasattr(response, 'response_metadata'):
                metadata = response.response_metadata
                
                # Different providers use different keys
                prompt_tokens = 0
                completion_tokens = 0
                total_tokens = 0
                
                # Google Gemini
                if 'usage_metadata' in metadata:
                    usage = metadata['usage_metadata']
                    prompt_tokens = usage.get('prompt_token_count', 0)
                    completion_tokens = usage.get('candidates_token_count', 0)
                    total_tokens = usage.get('total_token_count', 0)
                
                # OpenAI
                elif 'token_usage' in metadata:
                    usage = metadata['token_usage']
                    prompt_tokens = usage.get('prompt_tokens', 0)
                    completion_tokens = usage.get('completion_tokens', 0)
                    total_tokens = usage.get('total_tokens', 0)
                
                # Anthropic
                elif 'usage' in metadata:
                    usage = metadata['usage']
                    prompt_tokens = usage.get('input_tokens', 0)
                    completion_tokens = usage.get('output_tokens', 0)
                    total_tokens = prompt_tokens + completion_tokens
                
                if total_tokens > 0:
                    usage_record = TokenUsage(
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        total_tokens=total_tokens,
                        model=self.config.model_name
                    )
                    self.token_tracker.add_usage(usage_record)
                    
        except Exception as e:
            logger.warning(f"Failed to track token usage: {e}")

    def send_message(self, message: str) -> Optional[str]:
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries + 1):
            try:
                logger.debug(f"Sending message (length: {len(message)})")

                # Add user message to history
                self.chat_history.append(HumanMessage(content=message))

                start_time = datetime.now()
                # Invoke the model with full chat history
                response = self.chat_model.invoke(self.chat_history)
                api_time = (datetime.now() - start_time).total_seconds()

                self.metrics.add_api_time(api_time)

                # Track token usage
                self._track_token_usage(response)

                # Check for tool calls
                tool_results = self.handle_tool_calls(response)
                
                if tool_results:
                    # Tools were called, invoke model again with tool results
                    logger.info("Tool calls processed, getting final response from LLM")
                    
                    start_time = datetime.now()
                    response = self.chat_model.invoke(self.chat_history)
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

    def handle_tool_calls(self, response) -> Optional[str]:
        """
        Handle tool calls from LLM response.
        
        Args:
            response: LangChain response object
            
        Returns:
            Tool results as formatted string, or None if no tool calls
        """
        try:
            # Check if response has tool calls
            if not hasattr(response, 'tool_calls') or not response.tool_calls:
                return None
            
            logger.info(f"Processing {len(response.tool_calls)} tool call(s)")
            
            tool_results = []
            
            for tool_call in response.tool_calls:
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
            
            # Format results
            if tool_results:
                return json.dumps(tool_results, indent=2)
            
            return None
            
        except Exception as e:
            logger.error(f"Error handling tool calls: {e}")
            logger.debug(traceback.format_exc())
            return None

    def process_proposal(self, proposal: CommandProposal) -> Optional[CommandResult]:
        logger.debug(f"Processing proposal: {proposal.action}")

        if proposal.action == AgentAction.COMPLETE:
            logger.info(f"Task completed: {proposal.message_to_user}")
            print(f"\n✅ Task Completed: {proposal.message_to_user}")
            return None

        elif proposal.action == AgentAction.ABORT:
            logger.warning(f"Task aborted: {proposal.message_to_user}")
            print(f"\n🛑 Task Aborted: {proposal.message_to_user}")
            return None

        elif proposal.action == AgentAction.REQUEST_CLARIFICATION:
            logger.info(f"Clarification requested: {proposal.message_to_user}")
            print(f"\n❓ Clarification Needed: {proposal.message_to_user}")
            return None
            
        elif proposal.action == AgentAction.USE_TOOL:
            # This should be handled by handle_tool_calls if the LLM uses native tool calling
            # But if it returns JSON with "use_tool" action, we handle it here
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
                        
                        # We need to feed this back to the LLM
                        # This is tricky because process_proposal is usually terminal for a turn
                        # For now, we'll just return it as a result
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

        elif proposal.action == AgentAction.EXECUTE_COMMAND:
            print(f"\n📋 Plan: {proposal.plan}")
            print(f"💻 Command: {proposal.command}")
            if proposal.requires_sudo:
                print("🔒 Requires sudo privileges")
            print(f"🤔 Reasoning: {proposal.reasoning}")

            # Validate command
            is_valid, error_msg, risk_level = self.validator.validate(proposal)

            if not is_valid:
                logger.warning(f"Command validation failed: {error_msg}")
                print(f"\n⚠️ Command blocked: {error_msg}")
                return CommandResult(
                    command=proposal.command,
                    status=CommandStatus.BLOCKED,
                    output=f"Security validation failed: {error_msg}",
                    execution_time=0,
                    blocked_reason=error_msg,
                    security_level=risk_level
                )

            # Ask for user confirmation
            if risk_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                confirm = input(f"\n⚠️ WARNING: This is a {risk_level} risk command. Execute? (yes/no): ")
            else:
                confirm = input("\nExecute this command? (Y/n): ")

            if confirm.lower() not in ['y', 'yes', '']:
                logger.info("Command cancelled by user")
                print("❌ Command cancelled.")
                return CommandResult(
                    command=proposal.command,
                    status=CommandStatus.BLOCKED,
                    output="Command cancelled by user",
                    execution_time=0,
                    blocked_reason="User cancelled"
                )

            # Execute command
            return self.executor.execute(proposal)

        return None

    def parse_response(self, response_text: str) -> Optional[CommandProposal]:
        try:
            # Clean up response (remove markdown code blocks if present)
            cleaned_text = re.sub(r'^```json\s*|\s*```$', '', response_text.strip(), flags=re.MULTILINE)
            
            data = json.loads(cleaned_text)
            return CommandProposal(**data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Raw response: {response_text}")
            return None
        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            return None

    def run(self):
        print(f"Zuck Agent initialized (Session: {self.session.session_id})")
        print("Type 'quit', 'exit', or 'bye' to end the session.")
        
        # Initial greeting
        try:
            print("\n🤖 Connecting to AI model...")
            initial_response = self.initialize()
            print(f"✅ {initial_response}")
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            return

        while self.session.is_active:
            try:
                user_input = input("\n👤 You: ").strip()

                if not user_input:
                    continue

                if user_input.lower() in ['quit', 'exit', 'bye']:
                    self.session.complete()
                    break

                # Send message to AI
                print("🤖 Zuck is thinking...")
                response_text = self.send_message(user_input)

                if not response_text:
                    print("❌ Failed to get response from AI.")
                    continue

                # Check if response is just text (from tool usage) or JSON
                try:
                    # Try to parse as JSON command proposal
                    proposal = self.parse_response(response_text)
                    
                    if proposal:
                        result = self.process_proposal(proposal)

                        if result:
                            self.session.add_result(result)

                            # Feed result back to AI
                            result_message = f"Command execution result:\nStatus: {result.status}\nOutput:\n{result.output}"
                            
                            # If it was a tool use from JSON, format differently
                            if result.command.startswith("tool:"):
                                result_message = f"Tool execution result:\n{result.output}"
                                
                            print("\n🤖 Analyzing result...")
                            self.send_message(result_message)
                    else:
                        # If not valid JSON, just print the text (might be a conversational response)
                        print(f"\n🤖 Zuck: {response_text}")
                        
                except Exception as e:
                    logger.error(f"Error in main loop: {e}")
                    print(f"❌ An error occurred: {e}")

            except KeyboardInterrupt:
                print("\n\n⚠️ Session interrupted by user.")
                self.session.complete()
                break
            except Exception as e:
                logger.critical(f"Critical error: {e}")
                traceback.print_exc()
                break

        # Print session summary
        summary = self.session.get_summary()
        print("\n" + "=" * 40)
        print("Session Summary")
        print("=" * 40)
        print(f"Duration: {summary['duration']}")
        print(f"Commands: {summary['total_commands']} (Success: {summary['successful']}, Failed: {summary['failed']})")
        
        # Token usage summary
        token_summary = self.token_tracker.get_summary()
        print(f"Tokens: {token_summary['total_tokens']} (Cost: {token_summary['estimated_cost']})")
        print("=" * 40)
