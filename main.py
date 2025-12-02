from google import genai
from google.genai import types
import subprocess
import platform
import re
import sys
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional, List, Dict, Any
from pathlib import Path
from enum import Enum
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator, ConfigDict
import json
from dataclasses import dataclass
from collections import defaultdict
import traceback
import time


# ==================== Logging Configuration ====================

class LogFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""

    COLORS = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[32m',  # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',  # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(session_id: str, log_dir: str = "logs") -> logging.Logger:
    """Setup comprehensive logging system"""

    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    # Create logger
    logger = logging.getLogger('zuck_agent')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler (INFO and above)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = LogFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)

    # File handler - rotating (DEBUG and above)
    file_handler = RotatingFileHandler(
        log_path / 'zuck_agent.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)

    # Session-specific handler
    session_handler = logging.FileHandler(
        log_path / f'session_{session_id}.log'
    )
    session_handler.setLevel(logging.DEBUG)
    session_handler.setFormatter(file_format)

    # Error handler (ERROR and above)
    error_handler = logging.FileHandler(
        log_path / 'errors.log'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_format)

    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(session_handler)
    logger.addHandler(error_handler)

    return logger


logger = logging.getLogger('zuck_agent')


# ==================== Token Usage Tracking ====================

class TokenUsage(BaseModel):
    """Token usage for a single API call"""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    timestamp: datetime = Field(default_factory=datetime.now)
    model: str = ""

    @property
    def cost_estimate(self) -> float:
        """Estimate cost based on Gemini pricing (approximate)"""
        # Gemini 2.0 Flash pricing (approximate, check current rates)
        prompt_cost_per_1k = 0.0001  # $0.0001 per 1K input tokens
        completion_cost_per_1k = 0.0003  # $0.0003 per 1K output tokens

        prompt_cost = (self.prompt_tokens / 1000) * prompt_cost_per_1k
        completion_cost = (self.completion_tokens / 1000) * completion_cost_per_1k

        return prompt_cost + completion_cost


class TokenTracker(BaseModel):
    """Track token usage across session"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    api_calls: List[TokenUsage] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)

    def add_usage(self, usage: TokenUsage):
        """Add token usage record"""
        self.api_calls.append(usage)
        logger.debug(
            f"Token usage - Prompt: {usage.prompt_tokens}, "
            f"Completion: {usage.completion_tokens}, "
            f"Total: {usage.total_tokens}, "
            f"Cost: ${usage.cost_estimate:.6f}"
        )

    @property
    def total_prompt_tokens(self) -> int:
        return sum(call.prompt_tokens for call in self.api_calls)

    @property
    def total_completion_tokens(self) -> int:
        return sum(call.completion_tokens for call in self.api_calls)

    @property
    def total_tokens(self) -> int:
        return sum(call.total_tokens for call in self.api_calls)

    @property
    def total_cost(self) -> float:
        return sum(call.cost_estimate for call in self.api_calls)

    @property
    def average_tokens_per_call(self) -> float:
        if not self.api_calls:
            return 0.0
        return self.total_tokens / len(self.api_calls)

    def get_summary(self) -> Dict[str, Any]:
        """Get usage summary"""
        return {
            "session_id": self.session_id,
            "total_api_calls": len(self.api_calls),
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "average_tokens_per_call": round(self.average_tokens_per_call, 2),
            "estimated_cost": f"${self.total_cost:.6f}",
            "session_duration": str(datetime.now() - self.start_time),
        }


# ==================== Performance Metrics ====================

class PerformanceMetrics(BaseModel):
    """Track performance metrics"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    command_execution_times: List[float] = Field(default_factory=list)
    api_response_times: List[float] = Field(default_factory=list)
    validation_times: List[float] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)

    def add_command_time(self, duration: float):
        self.command_execution_times.append(duration)

    def add_api_time(self, duration: float):
        self.api_response_times.append(duration)

    def add_validation_time(self, duration: float):
        self.validation_times.append(duration)

    @property
    def avg_command_time(self) -> float:
        if not self.command_execution_times:
            return 0.0
        return sum(self.command_execution_times) / len(self.command_execution_times)

    @property
    def avg_api_time(self) -> float:
        if not self.api_response_times:
            return 0.0
        return sum(self.api_response_times) / len(self.api_response_times)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_commands": len(self.command_execution_times),
            "total_api_calls": len(self.api_response_times),
            "avg_command_execution_time": f"{self.avg_command_time:.3f}s",
            "avg_api_response_time": f"{self.avg_api_time:.3f}s",
            "total_session_time": str(datetime.now() - self.start_time),
        }


# ==================== Pydantic Models ====================

class CommandStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class AgentAction(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    REQUEST_CLARIFICATION = "request_clarification"
    COMPLETE = "complete"
    ABORT = "abort"


class SecurityLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CommandProposal(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    action: AgentAction = Field(description="The action type")
    plan: str = Field(description="Brief explanation", min_length=10, max_length=500)
    command: Optional[str] = Field(default=None, max_length=1000)
    requires_sudo: bool = Field(default=False)
    expected_output: Optional[str] = Field(default=None)
    reasoning: Optional[str] = Field(default=None)
    message_to_user: Optional[str] = Field(default=None)

    @validator('command')
    def validate_command(cls, v, values):
        if values.get('action') == AgentAction.EXECUTE_COMMAND and not v:
            raise ValueError("Command required for execute_command action")
        return v


class CommandResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    command: str
    status: CommandStatus
    output: str
    exit_code: Optional[int] = None
    execution_time: float
    timestamp: datetime = Field(default_factory=datetime.now)
    blocked_reason: Optional[str] = None
    security_level: SecurityLevel = SecurityLevel.SAFE


class SystemInfo(BaseModel):
    system: str
    node: str
    release: str
    version: str
    machine: str
    processor: str
    available_tools: List[str]
    python_version: str = Field(default_factory=lambda: platform.python_version())

    @classmethod
    def gather(cls, available_tools: List[str]) -> 'SystemInfo':
        import shutil
        
        installed_tools = []
        for tool in available_tools:
            if shutil.which(tool):
                installed_tools.append(tool)
            else:
                logger.warning(f"Tool not found: {tool}")

        info = cls(
            system=platform.system(),
            node=platform.node(),
            release=platform.release(),
            version=platform.version(),
            machine=platform.machine(),
            processor=platform.processor(),
            available_tools=installed_tools
        )
        logger.info(f"System info gathered: {info.system} {info.release}")
        logger.info(f"Available tools: {', '.join(installed_tools)}")
        return info


class SessionState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    commands_executed: int = 0
    commands_blocked: int = 0
    commands_failed: int = 0
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    is_active: bool = True
    command_history: List[CommandResult] = Field(default_factory=list)
    error_count: int = 0
    warning_count: int = 0

    def add_result(self, result: CommandResult):
        self.command_history.append(result)

        if result.status == CommandStatus.SUCCESS:
            self.commands_executed += 1
            logger.info(f"✓ Command succeeded: {result.command[:50]}...")
        elif result.status == CommandStatus.BLOCKED:
            self.commands_blocked += 1
            logger.warning(f"✗ Command blocked: {result.blocked_reason}")
        elif result.status == CommandStatus.FAILED:
            self.commands_failed += 1
            logger.error(f"✗ Command failed: {result.command[:50]}...")
        elif result.status == CommandStatus.ERROR:
            self.error_count += 1
            logger.error(f"✗ Execution error: {result.output[:100]}")

    def complete(self):
        self.is_active = False
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        logger.info(
            f"Session completed - Duration: {duration}, "
            f"Commands: {self.commands_executed}, "
            f"Blocked: {self.commands_blocked}, "
            f"Failed: {self.commands_failed}"
        )

    def get_summary(self) -> Dict[str, Any]:
        duration = (self.end_time or datetime.now()) - self.start_time

        return {
            "session_id": self.session_id,
            "duration": str(duration),
            "total_commands": len(self.command_history),
            "successful": self.commands_executed,
            "blocked": self.commands_blocked,
            "failed": self.commands_failed,
            "errors": self.error_count,
            "warnings": self.warning_count,
            "success_rate": f"{(self.commands_executed / max(len(self.command_history), 1) * 100):.1f}%"
        }


class AgentConfig(BaseModel):
    max_commands: int = Field(default=50, gt=0, le=200)
    command_timeout: int = Field(default=60, gt=0, le=300)
    max_command_length: int = Field(default=1000, gt=0)
    allowed_tools: List[str] = Field(
        default_factory=lambda: [
            'nmap', 'whois', 'tcpdump', 'tshark', 'nc', 'netcat',
            'dig', 'nslookup', 'host', 'aircrack-ng', 'airodump-ng',
            'ls', 'cat', 'grep', 'find', 'ps', 'netstat', 'ss',
            'ip', 'ifconfig', 'ping', 'traceroute', 'curl', 'wget',
            'echo', 'pwd', 'cd', 'mkdir', 'touch', 'head', 'tail',
            'awk', 'sed', 'sort', 'uniq', 'wc', 'chmod', 'chown'
        ]
    )
    api_key_file: str = "apikey.txt"
    model_name: str = "gemini-2.5-pro"
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    log_directory: str = "logs"
    save_session_data: bool = True


# ==================== Security Components ====================

class SecurityValidator:
    """Enhanced security validation"""

    CRITICAL_PATTERNS = [
        (r'\brm\s+(-[rf]+\s+)?/(?!tmp|var/tmp)', SecurityLevel.CRITICAL, "Recursive delete from root"),
        (r'\bmkfs\b', SecurityLevel.CRITICAL, "Filesystem creation"),
        (r'\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/', SecurityLevel.CRITICAL, "Disk wipe"),
        (r':\(\)\{.*\|\:.*\&\}\;', SecurityLevel.CRITICAL, "Fork bomb"),
        (r'\bformat\b.*\b(disk|drive|partition)', SecurityLevel.CRITICAL, "Format disk"),
    ]

    HIGH_RISK_PATTERNS = [
        (r'\bshutdown\b', SecurityLevel.HIGH, "System shutdown"),
        (r'\breboot\b', SecurityLevel.HIGH, "System reboot"),
        (r'\binit\s+[06]', SecurityLevel.HIGH, "System halt/reboot"),
        (r'\bkillall\b', SecurityLevel.HIGH, "Kill all processes"),
        (r'\biptables\s+-F', SecurityLevel.HIGH, "Flush firewall"),
        (r'\bufw\s+disable', SecurityLevel.HIGH, "Disable firewall"),
        (r'/dev/(sd[a-z]|nvme[0-9])', SecurityLevel.HIGH, "Direct device access"),
    ]

    MEDIUM_RISK_PATTERNS = [
        (r'\bchmod\s+(-R\s+)?777', SecurityLevel.MEDIUM, "Insecure permissions"),
        (r'\bchown\s+-R.*/', SecurityLevel.MEDIUM, "Recursive ownership change"),
        (r'\bpkill\s+-9', SecurityLevel.MEDIUM, "Force kill processes"),
    ]

    @classmethod
    def analyze_command(cls, command: str) -> tuple[bool, SecurityLevel, Optional[str]]:
        command_lower = command.lower().strip()

        logger.debug(f"Analyzing command security: {command[:50]}...")

        for pattern, level, desc in cls.CRITICAL_PATTERNS:
            if re.search(pattern, command_lower):
                logger.critical(f"CRITICAL security issue detected: {desc}")
                return False, level, f"CRITICAL: {desc}"

        for pattern, level, desc in cls.HIGH_RISK_PATTERNS:
            if re.search(pattern, command_lower):
                logger.error(f"HIGH RISK command detected: {desc}")
                return False, level, f"HIGH RISK: {desc}"

        for pattern, level, desc in cls.MEDIUM_RISK_PATTERNS:
            if re.search(pattern, command_lower):
                logger.warning(f"Medium risk command: {desc}")

        if any(sep in command for sep in [';', '&&', '||']):
            parts = re.split(r'[;&|]+', command)
            for part in parts:
                is_safe, level, reason = cls.analyze_command(part.strip())
                if not is_safe:
                    return False, level, f"Unsafe in chain: {reason}"

        logger.debug("Command passed security checks")
        return True, SecurityLevel.SAFE, None


class CommandValidator:
    def __init__(self, config: AgentConfig):
        self.config = config
        logger.debug("CommandValidator initialized")

    def validate(self, proposal: CommandProposal) -> tuple[bool, Optional[str], SecurityLevel]:
        start_time = datetime.now()

        if proposal.action != AgentAction.EXECUTE_COMMAND:
            return True, None, SecurityLevel.SAFE

        command = proposal.command

        logger.debug(f"Validating command: {command}")

        if not command or not command.strip():
            return False, "Empty command", SecurityLevel.SAFE

        if len(command) > self.config.max_command_length:
            logger.warning(f"Command exceeds max length: {len(command)} > {self.config.max_command_length}")
            return False, f"Command exceeds max length ({self.config.max_command_length})", SecurityLevel.SAFE

        is_safe, risk_level, reason = SecurityValidator.analyze_command(command)

        validation_time = (datetime.now() - start_time).total_seconds()
        logger.debug(f"Validation completed in {validation_time:.3f}s")

        if not is_safe:
            return False, f"Security check failed [{risk_level}]: {reason}", risk_level

        base_cmd = command.split()[0].split('/')[-1]
        if base_cmd == 'sudo' and len(command.split()) > 1:
            base_cmd = command.split()[1].split('/')[-1]

        if base_cmd not in self.config.allowed_tools:
            logger.warning(f"Command '{base_cmd}' not in allowed tools list")

        return True, None, risk_level


# ==================== Command Executor ====================

class CommandExecutor:
    def __init__(self, config: AgentConfig, metrics: PerformanceMetrics):
        self.config = config
        self.metrics = metrics
        logger.debug("CommandExecutor initialized")

    def execute(self, proposal: CommandProposal) -> CommandResult:
        start_time = datetime.now()
        command = proposal.command

        logger.info(f"Executing command: {command}")

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout,
                env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
            )

            execution_time = (datetime.now() - start_time).total_seconds()
            self.metrics.add_command_time(execution_time)

            output = result.stdout.strip() if result.stdout else ""
            error = result.stderr.strip() if result.stderr else ""

            if result.returncode == 0:
                status = CommandStatus.SUCCESS
                final_output = output if output else "Command executed successfully (no output)"
                logger.info(f"Command succeeded in {execution_time:.3f}s")
            else:
                status = CommandStatus.FAILED
                final_output = f"Exit code {result.returncode}\n{error if error else output}"
                logger.error(f"Command failed with exit code {result.returncode}")

            logger.debug(f"Output length: {len(final_output)} characters")

            return CommandResult(
                command=command,
                status=status,
                output=final_output,
                exit_code=result.returncode,
                execution_time=execution_time
            )

        except subprocess.TimeoutExpired:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Command timeout after {self.config.command_timeout}s")
            return CommandResult(
                command=command,
                status=CommandStatus.TIMEOUT,
                output=f"Command timed out after {self.config.command_timeout}s",
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Execution error: {type(e).__name__}: {e}")
            logger.debug(traceback.format_exc())
            return CommandResult(
                command=command,
                status=CommandStatus.ERROR,
                output=f"Error: {type(e).__name__}: {str(e)}",
                execution_time=execution_time
            )


# ==================== AI Agent ====================

class ZuckAgent:
    SYSTEM_PROMPT = """You are Zuck, an expert cybersecurity assistant for Pop!_OS Linux systems.

Your responses MUST be valid JSON matching this exact schema:

{
  "action": "execute_command" | "request_clarification" | "complete" | "abort",
  "plan": "Brief description of what you're doing (10-500 chars)",
  "command": "exact command to run (only if action is execute_command)",
  "requires_sudo": true | false,
  "expected_output": "what output you expect from this command",
  "reasoning": "why this command is safe and necessary",
  "message_to_user": "message for user (for clarification/complete/abort actions)"
}

CRITICAL RULES:
1. Output ONLY valid JSON, no markdown, no explanation outside JSON
2. Propose ONE command at a time
3. NEVER suggest destructive commands (rm -rf /, mkfs, dd to devices, etc.)
4. Use only installed tools: nmap, whois, tcpdump, tshark, netcat, dig, nslookup, aircrack-ng
5. If task is complete, use action "complete" with message_to_user
6. If you cannot proceed safely, use action "abort" with explanation
7. Always provide clear reasoning for security-sensitive commands

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

        self.api_key = self._load_api_key()
        self.client = genai.Client(api_key=self.api_key)
        self.chat = None

        self.token_tracker = TokenTracker(session_id=self.session.session_id)
        self.metrics = PerformanceMetrics(session_id=self.session.session_id)

        self.validator = CommandValidator(config)
        self.executor = CommandExecutor(config, self.metrics)
        self.system_info = SystemInfo.gather(config.allowed_tools)

        logger.info(f"Configuration: {config.model_dump_json()}")

    def _load_api_key(self) -> str:
        try:
            api_path = Path(self.config.api_key_file)
            if not api_path.exists():
                logger.critical(f"API key file not found: {self.config.api_key_file}")
                raise FileNotFoundError(f"API key file not found: {self.config.api_key_file}")

            key = api_path.read_text().strip()
            if not key:
                logger.critical("API key file is empty")
                raise ValueError("API key file is empty")

            logger.info("API key loaded successfully")
            return key
        except Exception as e:
            logger.critical(f"Failed to load API key: {e}")
            sys.exit(1)

    def initialize(self) -> str:
        try:
            logger.info("Initializing chat session...")

            generation_config = types.GenerateContentConfig(
                temperature=self.config.temperature,
                response_mime_type="application/json"
            )

            self.chat = self.client.chats.create(
                model=self.config.model_name,
                config=generation_config
            )

            context_message = f"""{self.SYSTEM_PROMPT}

System Information:
{self.system_info.model_dump_json(indent=2)}

Respond with JSON only."""

            start_time = datetime.now()
            response = self.chat.send_message(context_message)
            api_time = (datetime.now() - start_time).total_seconds()

            self.metrics.add_api_time(api_time)

            # Track token usage
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                usage = TokenUsage(
                    prompt_tokens=getattr(response.usage_metadata, 'prompt_token_count', 0),
                    completion_tokens=getattr(response.usage_metadata, 'candidates_token_count', 0),
                    total_tokens=getattr(response.usage_metadata, 'total_token_count', 0),
                    model=self.config.model_name
                )
                self.token_tracker.add_usage(usage)

            logger.info(f"Chat initialized successfully in {api_time:.3f}s")
            logger.info(f"Model: {self.config.model_name}, Temperature: {self.config.temperature}")

            return "Zuck agent initialized and ready."

        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            logger.debug(traceback.format_exc())
            raise

    def parse_response(self, response_text: str) -> Optional[CommandProposal]:
        try:
            logger.debug(f"Parsing response (length: {len(response_text)})")

            response_text = response_text.strip()

            if response_text.startswith('```'):
                response_text = re.sub(r'^```(?:json)?\s*\n?', '', response_text)
                response_text = re.sub(r'\n?```\s*$', '', response_text)

            data = json.loads(response_text)
            proposal = CommandProposal(**data)

            logger.info(f"Parsed proposal: action={proposal.action}, plan={proposal.plan[:50]}...")

            return proposal

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            logger.debug(f"Response text: {response_text[:500]}")
            return None
        except Exception as e:
            logger.error(f"Proposal parsing error: {e}")
            logger.debug(traceback.format_exc())
            return None

    def send_message(self, message: str) -> Optional[str]:
        max_retries = 3
        base_delay = 2
        
        for attempt in range(max_retries + 1):
            try:
                logger.debug(f"Sending message (length: {len(message)})")

                start_time = datetime.now()
                response = self.chat.send_message(message)
                api_time = (datetime.now() - start_time).total_seconds()

                self.metrics.add_api_time(api_time)

                # Track token usage
                if hasattr(response, 'usage_metadata') and response.usage_metadata:
                    usage = TokenUsage(
                        prompt_tokens=getattr(response.usage_metadata, 'prompt_token_count', 0),
                        completion_tokens=getattr(response.usage_metadata, 'candidates_token_count', 0),
                        total_tokens=getattr(response.usage_metadata, 'total_token_count', 0),
                        model=self.config.model_name
                    )
                    self.token_tracker.add_usage(usage)

                logger.debug(f"Received response in {api_time:.3f}s (length: {len(response.text)})")

                return response.text

            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
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

    def process_proposal(self, proposal: CommandProposal) -> Optional[CommandResult]:
        logger.debug(f"Processing proposal: {proposal.action}")

        if proposal.action == AgentAction.COMPLETE:
            logger.info(f"Task completed: {proposal.message_to_user}")
            print(f"\n✅ {proposal.message_to_user}")
            self.session.complete()
            return None

        if proposal.action == AgentAction.ABORT:
            logger.warning(f"Task aborted: {proposal.message_to_user}")
            print(f"\n🛑 {proposal.message_to_user}")
            self.session.complete()
            return None

        if proposal.action == AgentAction.REQUEST_CLARIFICATION:
            logger.info(f"Clarification needed: {proposal.message_to_user}")
            print(f"\n❓ {proposal.message_to_user}")
            user_input = input("Your response: ").strip()
            response_text = self.send_message(user_input)
            if response_text:
                return self.process_proposal(self.parse_response(response_text))
            return None

        if proposal.action == AgentAction.EXECUTE_COMMAND:
            is_valid, error, security_level =is_valid, error, security_level = self.validator.validate(proposal)

            if not is_valid:
                result = CommandResult(
                    command=proposal.command,
                    status=CommandStatus.BLOCKED,
                    output="",
                    execution_time=0.0,
                    blocked_reason=error,
                    security_level=security_level
                )
                self.session.add_result(result)
                logger.warning(f"Command blocked: {error}")
                print(f"\n🚫 BLOCKED: {error}\n")
                return result

            # Display command info
            print(f"\n{'='*60}")
            print(f"📋 Plan: {proposal.plan}")
            if proposal.reasoning:
                print(f"💭 Reasoning: {proposal.reasoning}")
            if proposal.expected_output:
                print(f"🎯 Expected: {proposal.expected_output}")
            if proposal.requires_sudo:
                print(f"⚠️  Note: This command may require sudo privileges")
            print(f"⚡ Executing: {proposal.command}")
            print(f"{'='*60}")

            # Execute
            result = self.executor.execute(proposal)
            result.security_level = security_level
            self.session.add_result(result)

            # Display result
            status_emoji = {
                CommandStatus.SUCCESS: "✅",
                CommandStatus.FAILED: "❌",
                CommandStatus.TIMEOUT: "⏱️",
                CommandStatus.ERROR: "🚨"
            }

            print(f"\n{status_emoji.get(result.status, '❓')} Status: {result.status}")
            print(f"⏱️  Execution time: {result.execution_time:.3f}s")
            if result.exit_code is not None:
                print(f"🔢 Exit code: {result.exit_code}")
            print(f"\n📤 Output:")
            print("-" * 60)
            print(result.output)
            print("-" * 60 + "\n")

            return result

        return None

    def run(self, user_request: str):
        """Main execution loop with comprehensive logging"""
        logger.info("="*80)
        logger.info(f"Starting session: {self.session.session_id}")
        logger.info(f"User request: {user_request}")
        logger.info("="*80)

        print(f"\n{'='*60}")
        print(f"🔐 Zuck Cybersecurity Agent")
        print(f"📅 Session: {self.session.session_id}")
        print(f"{'='*60}\n")

        # Send initial request
        logger.info("Sending initial request to AI...")
        response_text = self.send_message(user_request)

        if not response_text:
            logger.error("Failed to get initial response from AI")
            print("❌ Failed to get initial response from AI")
            return

        proposal = self.parse_response(response_text)
        if not proposal:
            logger.error("Failed to parse AI response")
            print("❌ Failed to parse AI response")
            return

        # Process initial proposal
        result = self.process_proposal(proposal)

        # Main loop
        iteration = 0
        while self.session.is_active and self.session.commands_executed < self.config.max_commands:
            iteration += 1
            logger.info(f"Loop iteration {iteration}")

            if result is None:
                logger.info("No result, breaking loop")
                break

            # Send result back to AI
            feedback = {
                "command": result.command,
                "status": result.status,
                "output": result.output,
                "execution_time": result.execution_time,
                "exit_code": result.exit_code
            }

            logger.debug(f"Sending feedback to AI: status={result.status}")
            response_text = self.send_message(json.dumps(feedback))

            if not response_text:
                logger.error("Failed to get response from AI")
                print("❌ Failed to get response from AI")
                break

            proposal = self.parse_response(response_text)
            if not proposal:
                logger.error("Failed to parse AI response")
                print("❌ Failed to parse AI response")
                break

            result = self.process_proposal(proposal)

        if self.session.commands_executed >= self.config.max_commands:
            logger.warning(f"Reached maximum command limit ({self.config.max_commands})")
            print(f"\n⚠️  Reached maximum command limit ({self.config.max_commands})")

        # Finalize session
        if self.session.is_active:
            self.session.complete()

        # Display comprehensive summary
        self._display_summary()

        # Save session data
        if self.config.save_session_data:
            self._save_session_data()

        logger.info("="*80)
        logger.info("Session completed successfully")
        logger.info("="*80)

    def _display_summary(self):
        """Display comprehensive session summary"""
        print(f"\n{'='*60}")
        print("📊 SESSION SUMMARY")
        print(f"{'='*60}\n")

        # Session stats
        session_summary = self.session.get_summary()
        print("📈 Session Statistics:")
        for key, value in session_summary.items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")

        print(f"\n{'='*60}\n")

        # Token usage
        token_summary = self.token_tracker.get_summary()
        print("🎫 Token Usage:")
        for key, value in token_summary.items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")

        print(f"\n{'='*60}\n")

        # Performance metrics
        perf_summary = self.metrics.get_summary()
        print("⚡ Performance Metrics:")
        for key, value in perf_summary.items():
            print(f"  • {key.replace('_', ' ').title()}: {value}")

        print(f"\n{'='*60}\n")

        # Command history summary
        if self.session.command_history:
            print("📜 Command History:")
            for i, cmd_result in enumerate(self.session.command_history[-5:], 1):  # Last 5
                status_symbol = {
                    CommandStatus.SUCCESS: "✅",
                    CommandStatus.FAILED: "❌",
                    CommandStatus.BLOCKED: "🚫",
                    CommandStatus.TIMEOUT: "⏱️",
                    CommandStatus.ERROR: "🚨"
                }.get(cmd_result.status, "❓")

                print(f"  {i}. {status_symbol} {cmd_result.command[:50]}... "
                      f"({cmd_result.execution_time:.2f}s)")

        print(f"\n{'='*60}\n")

        # Security summary
        security_stats = self._get_security_stats()
        print("🔒 Security Summary:")
        for key, value in security_stats.items():
            print(f"  • {key}: {value}")

        print(f"\n{'='*60}\n")

        logger.info("Summary displayed to user")

    def _get_security_stats(self) -> Dict[str, Any]:
        """Calculate security statistics"""
        security_levels = defaultdict(int)

        for cmd_result in self.session.command_history:
            security_levels[cmd_result.security_level] += 1

        return {
            "Total Commands Analyzed": len(self.session.command_history),
            "Blocked Commands": self.session.commands_blocked,
            "Safe Commands": security_levels.get(SecurityLevel.SAFE, 0),
            "Low Risk": security_levels.get(SecurityLevel.LOW, 0),
            "Medium Risk": security_levels.get(SecurityLevel.MEDIUM, 0),
            "High Risk": security_levels.get(SecurityLevel.HIGH, 0),
            "Critical Risk": security_levels.get(SecurityLevel.CRITICAL, 0),
        }

    def _save_session_data(self):
        """Save comprehensive session data to JSON"""
        try:
            log_dir = Path(self.config.log_directory)
            log_dir.mkdir(exist_ok=True)

            session_data = {
                "metadata": {
                    "session_id": self.session.session_id,
                    "start_time": self.session.start_time.isoformat(),
                    "end_time": self.session.end_time.isoformat() if self.session.end_time else None,
                    "model": self.config.model_name,
                    "temperature": self.config.temperature,
                },
                "session_summary": self.session.get_summary(),
                "token_usage": self.token_tracker.get_summary(),
                "performance_metrics": self.metrics.get_summary(),
                "security_stats": self._get_security_stats(),
                "system_info": self.system_info.model_dump(),
                "configuration": self.config.model_dump(),
                "command_history": [
                    {
                        "timestamp": cmd.timestamp.isoformat(),
                        "command": cmd.command,
                        "status": cmd.status,
                        "output": cmd.output[:500],  # Truncate long outputs
                        "execution_time": cmd.execution_time,
                        "exit_code": cmd.exit_code,
                        "security_level": cmd.security_level,
                        "blocked_reason": cmd.blocked_reason
                    }
                    for cmd in self.session.command_history
                ],
                "token_details": [
                    {
                        "timestamp": usage.timestamp.isoformat(),
                        "prompt_tokens": usage.prompt_tokens,
                        "completion_tokens": usage.completion_tokens,
                        "total_tokens": usage.total_tokens,
                        "cost_estimate": usage.cost_estimate
                    }
                    for usage in self.token_tracker.api_calls
                ]
            }

            # Save main session file
            session_file = log_dir / f"session_{self.session.session_id}.json"
            session_file.write_text(json.dumps(session_data, indent=2, default=str))

            logger.info(f"Session data saved: {session_file}")
            print(f"💾 Session data saved: {session_file}")

            # Save summary file
            summary_file = log_dir / f"summary_{self.session.session_id}.txt"
            with open(summary_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write(f"ZUCK AGENT SESSION SUMMARY\n")
                f.write(f"Session ID: {self.session.session_id}\n")
                f.write("="*80 + "\n\n")

                f.write("SESSION STATISTICS\n")
                f.write("-"*80 + "\n")
                for key, value in self.session.get_summary().items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")

                f.write("\n" + "="*80 + "\n\n")

                f.write("TOKEN USAGE\n")
                f.write("-"*80 + "\n")
                for key, value in self.token_tracker.get_summary().items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")

                f.write("\n" + "="*80 + "\n\n")

                f.write("PERFORMANCE METRICS\n")
                f.write("-"*80 + "\n")
                for key, value in self.metrics.get_summary().items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")

                f.write("\n" + "="*80 + "\n\n")

                f.write("SECURITY SUMMARY\n")
                f.write("-"*80 + "\n")
                for key, value in self._get_security_stats().items():
                    f.write(f"{key}: {value}\n")

                f.write("\n" + "="*80 + "\n\n")

                f.write("COMMAND HISTORY\n")
                f.write("-"*80 + "\n")
                for i, cmd in enumerate(self.session.command_history, 1):
                    f.write(f"\n{i}. Command: {cmd.command}\n")
                    f.write(f"   Status: {cmd.status}\n")
                    f.write(f"   Time: {cmd.execution_time:.3f}s\n")
                    f.write(f"   Security Level: {cmd.security_level}\n")
                    if cmd.blocked_reason:
                        f.write(f"   Blocked: {cmd.blocked_reason}\n")

                f.write("\n" + "="*80 + "\n")

            logger.info(f"Summary saved: {summary_file}")
            print(f"📄 Summary saved: {summary_file}")

        except Exception as e:
            logger.error(f"Failed to save session data: {e}")
            logger.debug(traceback.format_exc())


# ==================== Analytics & Reporting ====================

class SessionAnalytics:
    """Analyze session data and generate reports"""

    @staticmethod
    def load_session(session_file: Path) -> Dict[str, Any]:
        """Load session data from JSON file"""
        try:
            with open(session_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return {}

    @staticmethod
    def generate_report(session_data: Dict[str, Any]) -> str:
        """Generate detailed analytics report"""
        report = []
        report.append("="*80)
        report.append("ZUCK AGENT ANALYTICS REPORT")
        report.append("="*80)
        report.append("")

        # Session overview
        metadata = session_data.get('metadata', {})
        report.append("SESSION OVERVIEW")
        report.append("-"*80)
        report.append(f"Session ID: {metadata.get('session_id')}")
        report.append(f"Model: {metadata.get('model')}")
        report.append(f"Start Time: {metadata.get('start_time')}")
        report.append(f"End Time: {metadata.get('end_time')}")
        report.append("")

        # Performance analysis
        summary = session_data.get('session_summary', {})
        report.append("PERFORMANCE ANALYSIS")
        report.append("-"*80)
        report.append(f"Total Commands: {summary.get('total_commands')}")
        report.append(f"Success Rate: {summary.get('success_rate')}")
        report.append(f"Duration: {summary.get('duration')}")
        report.append("")

        # Cost analysis
        token_usage = session_data.get('token_usage', {})
        report.append("COST ANALYSIS")
        report.append("-"*80)
        report.append(f"Total API Calls: {token_usage.get('total_api_calls')}")
        report.append(f"Total Tokens: {token_usage.get('total_tokens')}")
        report.append(f"Estimated Cost: {token_usage.get('estimated_cost')}")
        report.append(f"Avg Tokens/Call: {token_usage.get('average_tokens_per_call')}")
        report.append("")

        # Security analysis
        security = session_data.get('security_stats', {})
        report.append("SECURITY ANALYSIS")
        report.append("-"*80)
        for key, value in security.items():
            report.append(f"{key}: {value}")
        report.append("")

        # Command breakdown
        cmd_history = session_data.get('command_history', [])
        if cmd_history:
            report.append("COMMAND BREAKDOWN")
            report.append("-"*80)

            status_counts = defaultdict(int)
            for cmd in cmd_history:
                status_counts[cmd['status']] += 1

            for status, count in status_counts.items():
                percentage = (count / len(cmd_history)) * 100
                report.append(f"{status}: {count} ({percentage:.1f}%)")

        report.append("")
        report.append("="*80)

        return "\n".join(report)

    @staticmethod
    def compare_sessions(session_files: List[Path]) -> str:
        """Compare multiple sessions"""
        sessions = [SessionAnalytics.load_session(f) for f in session_files]

        report = []
        report.append("="*80)
        report.append("SESSION COMPARISON REPORT")
        report.append("="*80)
        report.append("")

        for i, session in enumerate(sessions, 1):
            summary = session.get('session_summary', {})
            token = session.get('token_usage', {})

            report.append(f"Session {i}: {session.get('metadata', {}).get('session_id')}")
            report.append("-"*80)
            report.append(f"  Commands: {summary.get('total_commands')}")
            report.append(f"  Success Rate: {summary.get('success_rate')}")
            report.append(f"  Cost: {token.get('estimated_cost')}")
            report.append(f"  Duration: {summary.get('duration')}")
            report.append("")

        report.append("="*80)
        return "\n".join(report)


# ==================== CLI Interface ====================

def print_banner():
    """Print ASCII banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗██╗   ██╗ ██████╗██╗  ██╗                         ║
║   ╚══███╔╝██║   ██║██╔════╝██║ ██╔╝                         ║
║     ███╔╝ ██║   ██║██║     █████╔╝                          ║
║    ███╔╝  ██║   ██║██║     ██╔═██╗                          ║
║   ███████╗╚██████╔╝╚██████╗██║  ██╗                         ║
║   ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝                         ║
║                                                              ║
║        🔐 Cybersecurity Agent with AI                       ║
║        📊 With Comprehensive Logging & Metrics              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point with enhanced CLI"""
    print_banner()

    print("\n⚠️  SECURITY NOTICE")
    print("="*60)
    print("This agent executes system commands with safety checks.")
    print("All actions are logged, validated, and tracked.")
    print("Session data is saved for audit purposes.")
    print("="*60)

    try:
        # Load configuration
        config = AgentConfig()

        print(f"\n📋 Configuration:")
        print(f"  • Model: {config.model_name}")
        print(f"  • Max Commands: {config.max_commands}")
        print(f"  • Command Timeout: {config.command_timeout}s")
        print(f"  • Temperature: {config.temperature}")
        print(f"  • Log Directory: {config.log_directory}")

        # Initialize agent
        print(f"\n🔄 Initializing agent...")
        agent = ZuckAgent(config)
        agent.initialize()

        print("\n✅ Agent ready!")
        print("="*60)

        # Get user request
        print("\n💡 Example requests:")
        print("  • Scan my local network for active hosts")
        print("  • Check open ports on localhost")
        print("  • Analyze network traffic for 10 seconds")
        print("  • Look up DNS records for google.com")
        print("")

        user_request = input("🎯 What would you like me to help with? :  ").strip()

        if not user_request:
            print("\n❌ No request provided. Exiting.")
            return

        if user_request.lower() in ['exit', 'quit', 'q']:
            print("\n👋 Goodbye!")
            return

        # Run agent
        print("\n" + "="*60)
        print("🚀 Starting execution...")
        print("="*60)

        agent.run(user_request)

        print("\n" + "="*60)
        print("✅ Session completed successfully!")
        print("="*60)

    except KeyboardInterrupt:
        print("\n\n⚠️  Session interrupted by user")
        logger.info("Session interrupted by user (KeyboardInterrupt)")
        if 'agent' in locals():
            agent.session.complete()
            agent._save_session_data()
        sys.exit(0)

    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Fatal error: {e}")
        print("Check logs for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()