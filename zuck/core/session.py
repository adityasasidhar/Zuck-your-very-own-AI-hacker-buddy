"""
Session state management for the agent.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

from zuck.core.models import CommandResult, CommandStatus


class SessionState(BaseModel):
    """Manages the state of an agent session."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S")
    )
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
        """Add a command result to the session history."""
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
        """Mark the session as complete."""
        self.is_active = False
        self.end_time = datetime.now()

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the session."""
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
