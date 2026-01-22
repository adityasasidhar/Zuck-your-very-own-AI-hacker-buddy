"""
System information gathering.
"""

import logging
import platform
import shutil
from typing import List

from pydantic import BaseModel, Field

logger = logging.getLogger('zuck_agent')


class SystemInfo(BaseModel):
    """System information for the agent context."""
    system: str
    node: str
    release: str
    version: str
    machine: str
    processor: str
    available_tools: List[str]
    python_version: str = Field(default_factory=lambda: platform.python_version())

    @classmethod
    def gather(cls, allowed_tools: List[str]) -> 'SystemInfo':
        """
        Gather system information.
        
        Args:
            allowed_tools: List of tools to check for availability
            
        Returns:
            SystemInfo instance with gathered data
        """
        # Shell builtins that don't have executable files
        SHELL_BUILTINS = {
            'cd', 'echo', 'pwd', 'export', 'source', 
            'alias', 'bg', 'fg', 'jobs', 'history'
        }
        
        installed_tools = []
        for tool in allowed_tools:
            if tool in SHELL_BUILTINS:
                installed_tools.append(tool)
            elif shutil.which(tool):
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
