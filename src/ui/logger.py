import sys
import logging
import threading
from pathlib import Path
from typing import Any


class Logger:
    def __init__(self, name: str, log_file: str, log_level=logging.INFO):
        """
        Initialize the Logger class.

        Args:
            name (str): Name of the logger.
            log_file (str): Path to the log file.
            log_level (int, optional): Logging level, defaults to logging.INFO.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        self._log_lock = threading.Lock()

        # Prevent adding multiple handlers to the same logger instance
        if not self.logger.handlers:
            # Ensure the parent directory exists
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            
            # File handler
            fh = logging.FileHandler(log_file)
            fh.setLevel(log_level)

            # Console handler
            ch = logging.StreamHandler()
            ch.setLevel(log_level)
            self.console_handler = ch  # Save handler as instance attribute

            # Formatter
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            fh.setFormatter(formatter)
            ch.setFormatter(formatter)

            # Add handlers
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

    def print_log(self, *args: Any) -> None:
        """
        Output messages to log file only.
        The last argument can optionally be a log level string ('debug', 'info', 'warning', 'error').
        """
        if not args:
            return

        level = 'info'
        message_parts = list(args)

        if isinstance(args[-1], str) and args[-1].upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            level = args[-1].lower()
            message_parts.pop()
        
        message = " ".join(map(str, message_parts))

        with self._log_lock:
            if self.console_handler in self.logger.handlers:
                self.logger.removeHandler(self.console_handler)
            
            log_method = getattr(self.logger, level, self.logger.info)
            log_method(message)

            if self.console_handler not in self.logger.handlers:
                self.logger.addHandler(self.console_handler)

    def print_console(self, message: str, level: str = 'info'):
        with self._log_lock:
            if level.lower() == 'info':
                self.logger.info(message)
            elif level.lower() == 'warning':
                self.logger.warning(message)
            elif level.lower() == 'error':
                self.logger.error(message)
            elif level.lower() == 'debug':
                self.logger.debug(message)
            else:
                self.logger.info(message) # Default to info

# Global logger instance for easy access from other modules
ui_logger = Logger(name="RepoAudit", log_file="log/repoaudit_ui.log")
