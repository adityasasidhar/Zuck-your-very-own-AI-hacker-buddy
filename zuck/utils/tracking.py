"""
Token and performance tracking.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

from pydantic import BaseModel, Field, ConfigDict

from zuck.core.models import TokenUsage

logger = logging.getLogger('zuck_agent')


class TokenTracker(BaseModel):
    """Track token usage across session."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    api_calls: List[TokenUsage] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)

    def add_usage(self, usage: TokenUsage):
        """Add token usage record."""
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
        """Get usage summary."""
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


class PerformanceMetrics(BaseModel):
    """Track performance metrics."""
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
