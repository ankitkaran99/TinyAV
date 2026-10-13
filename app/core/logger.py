import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

LOGGER_NAME = "TinyAV"

def get_default_log_dir() -> str:
    local_app_data = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    log_dir = os.path.join(local_app_data, "TinyAV", "logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def get_log_file_path() -> str:
    return os.path.join(get_default_log_dir(), "tinyav.log")

def setup_logger(log_level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger

    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(threadName)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # Rotating File Handler
    try:
        log_file = get_log_file_path()
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
    except Exception as exc:
        print(f"Warning: Failed to initialize file logger: {exc}")

    return logger

def get_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        return setup_logger()
    return logger
