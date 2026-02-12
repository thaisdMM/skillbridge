"""Logging configuration for the application."""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure application-wide logging.

    Args:
        level: logging level (logging.DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured root logger

    Note:
        Call this once at application startup.
        In tests, use logging.DEBUG for detailed output.
    """

    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Console handler (output to terminal)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Format: timestamp - logger name - level - message
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(formatter)

    # Add handler to root logger
    root_logger.addHandler(console_handler)

    return root_logger
