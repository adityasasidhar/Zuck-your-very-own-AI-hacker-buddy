import platform
import shutil
import logging
from typing import List
from pydantic import BaseModel, Field

logger = logging.getLogger('zuck_agent')

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
        # Shell builtins that don't have executable files
        SHELL_BUILTINS = {'cd', 'echo', 'pwd', 'export', 'source', 'alias', 'bg', 'fg', 'jobs', 'history'}
        
        installed_tools = []
        for tool in available_tools:
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
