"""
SecureRecon - Logging Module
Provides a simple scan-level logger that writes timestamped events
(scan start/end, errors, timeouts) to a per-scan log file under logs/.
"""

import os
import logging
from datetime import datetime

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")

_logger_instance = None
_log_file_path = None


def init_logger():
    """
    Initialize a fresh logger for this scan run, writing to a
    timestamped file under logs/. Returns the configured logger.
    Safe to call once at program start.
    """
    global _logger_instance, _log_file_path

    os.makedirs(LOGS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    _log_file_path = os.path.join(LOGS_DIR, f"{timestamp}_scan.log")

    logger = logging.getLogger("SecureRecon")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()  # avoid duplicate handlers if called more than once

    file_handler = logging.FileHandler(_log_file_path)
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                   datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _logger_instance = logger
    return logger


def get_logger():
    """Return the active logger, initializing one if none exists yet."""
    global _logger_instance
    if _logger_instance is None:
        return init_logger()
    return _logger_instance


def get_log_file_path():
    """Return the path of the current scan's log file."""
    return _log_file_path


def log_scan_start(target, profile):
    logger = get_logger()
    logger.info(f"Scan started - Target: {target} - Profile: {profile}")


def log_scan_end(target, overall_risk):
    logger = get_logger()
    logger.info(f"Scan completed - Target: {target} - Overall Risk: {overall_risk}")


def log_error(message):
    logger = get_logger()
    logger.error(message)


def log_warning(message):
    logger = get_logger()
    logger.warning(message)


def log_info(message):
    logger = get_logger()
    logger.info(message)
