"""Logging configuration for the chaos engineering framework."""

import logging
from pathlib import Path

_LOGGER_NAME = "joshuas_chaos"
_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the named logger, initializing handlers on first call."""
    logger_name = name or _LOGGER_NAME
    return logging.getLogger(logger_name)


def setup_logging(log_dir: Path | None = None) -> logging.Logger:
    """Configure file-based logging for the framework.

    No console handler is added by default. Only sanitized summaries
    should be passed to this logger — never raw boto3 responses.
    """
    if log_dir is None:
        log_dir = Path(__file__).parents[2] / "logs"

    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(_LOGGER_NAME)

    # Avoid adding duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(_LOG_FORMAT)

    # General log file
    file_handler = logging.FileHandler(log_dir / "joshuas_chaos.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Error-only log file
    error_handler = logging.FileHandler(log_dir / "error.log")
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)

    # Prevent propagation to root logger (which may have a console handler)
    logger.propagate = False

    return logger
