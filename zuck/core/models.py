"""
Pydantic models for agent operations.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any

from pydantic import BaseModel, Field, validator, ConfigDict


class CommandStatus(str, Enum):
    """Status of command execution."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class AgentAction(str, Enum):
    """Actions the agent can take."""
    EXECUTE_COMMAND = "execute_command"
    USE_TOOL = "use_tool"
    REQUEST_CLARIFICATION = "request_clarification"
    COMPLETE = "complete"
    ABORT = "abort"


class SecurityLevel(str, Enum):
    """Security risk level for commands."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CommandProposal(BaseModel):
    """Proposal from the LLM for an action to take."""
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
    """Result of command execution."""
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
    """Token usage for a single API call."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    timestamp: datetime = Field(default_factory=datetime.now)
    model: str = ""

    @property
    def cost_estimate(self) -> float:
        """Estimate cost based on Gemini pricing (approximate)."""
        # Gemini 2.0 Flash pricing (approximate, check current rates)
        prompt_cost_per_1k = 0.0001  # $0.0001 per 1K input tokens
        completion_cost_per_1k = 0.0003  # $0.0003 per 1K output tokens

        prompt_cost = (self.prompt_tokens / 1000) * prompt_cost_per_1k
        completion_cost = (self.completion_tokens / 1000) * completion_cost_per_1k

        return prompt_cost + completion_cost
