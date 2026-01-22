"""
Logging setup with colors and file rotation.
"""

import logging
import sys
import warnings
from logging.handlers import RotatingFileHandler
from pathlib import Path


# Suppress noisy third-party loggers
def suppress_noisy_loggers():
    """Suppress verbose logs from langchain and other libraries."""
    noisy_loggers = [
        'httpx',
        'httpcore',
        'urllib3',
        'requests',
        'langchain',
        'langchain_core',
        'langchain_google_genai',
        'langchain_openai',
        'langchain_anthropic',
        'langchain_community',
        'google.api_core',
        'google.auth',
        'tenacity',
    ]
    
    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.ERROR)
    
    # Suppress retry warnings
    warnings.filterwarnings('ignore', message='.*Retrying.*')


class LogFormatter(logging.Formatter):
    """Custom formatter with colors for console output."""

    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'

    def format(self, record):
        if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class CleanConsoleHandler(logging.StreamHandler):
    """Console handler that filters out noisy messages."""
    
    NOISE_PATTERNS = [
        'Retrying langchain',
        'ResourceExhausted',
        'rate_limit',
        '429',
        'quota',
        'Failed to parse JSON',
    ]
    
    def emit(self, record):
        msg = record.getMessage()
        # Skip noisy messages
        for pattern in self.NOISE_PATTERNS:
            if pattern.lower() in msg.lower():
                return
        super().emit(record)


def setup_logging(session_id: str, log_dir: str = "logs") -> logging.Logger:
    """
    Setup comprehensive logging system.
    
    Args:
        session_id: Unique session identifier
        log_dir: Directory for log files
        
    Returns:
        Configured logger instance
    """
    # Suppress noisy loggers first
    suppress_noisy_loggers()
    
    # Create logs directory
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)

    # Create logger
    logger = logging.getLogger('zuck_agent')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # Console handler (INFO and above) - uses clean handler
    console_handler = CleanConsoleHandler(sys.stdout)
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
