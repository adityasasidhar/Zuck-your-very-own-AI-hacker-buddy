"""
Command execution with safety and logging.
"""

import subprocess
import logging
import traceback
from datetime import datetime

from zuck.core.models import CommandProposal, CommandResult, CommandStatus
from zuck.core.config import AgentConfig
from zuck.utils.tracking import PerformanceMetrics

logger = logging.getLogger('zuck_agent')


class CommandExecutor:
    """Executes shell commands with safety measures."""
    
    def __init__(self, config: AgentConfig, metrics: PerformanceMetrics):
        self.config = config
        self.metrics = metrics
        logger.debug("CommandExecutor initialized")

    def execute(self, proposal: CommandProposal) -> CommandResult:
        """
        Execute a validated command.
        
        Args:
            proposal: The command proposal to execute
            
        Returns:
            CommandResult with output and status
        """
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
