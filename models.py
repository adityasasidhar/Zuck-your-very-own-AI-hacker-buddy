from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, validator, ConfigDict

class CommandStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"

class AgentAction(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    USE_TOOL = "use_tool"
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
    tool_name: Optional[str] = Field(default=None)
    tool_input: Optional[Dict[str, Any]] = Field(default=None)
    requires_sudo: bool = Field(default=False)
    expected_output: Optional[str] = Field(default=None)
    reasoning: Optional[str] = Field(default=None)
    message_to_user: Optional[str] = Field(default=None)

    @validator('command')
    def validate_command(cls, v, values):
        if values.get('action') == AgentAction.EXECUTE_COMMAND and not v:
            raise ValueError("Command required for execute_command action")
        return v

    @validator('tool_name')
    def validate_tool(cls, v, values):
        if values.get('action') == AgentAction.USE_TOOL and not v:
            raise ValueError("Tool name required for use_tool action")
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
        elif result.status == CommandStatus.BLOCKED:
            self.commands_blocked += 1
        elif result.status == CommandStatus.FAILED:
            self.commands_failed += 1
        elif result.status == CommandStatus.ERROR:
            self.error_count += 1

    def complete(self):
        self.is_active = False
        self.end_time = datetime.now()

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
