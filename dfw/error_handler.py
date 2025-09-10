"""Centralized error handling module for Digital Forensics Workbench.

This module provides consistent error handling, logging, and user feedback mechanisms.
"""

import os
import sys
import traceback
import logging
from datetime import datetime
from typing import Optional, Callable, Any
from functools import wraps
from tkinter import messagebox


class DFWErrorHandler:
    """Centralized error handler for the Digital Forensics Workbench."""
    
    def __init__(self, log_directory: str = None):
        """Initialize error handler with logging configuration.
        
        Args:
            log_directory: Directory for log files. Defaults to ~/DFW_Logs
        """
        if log_directory is None:
            log_directory = os.path.expanduser("~/DFW_Logs")
        
        self.log_directory = log_directory
        os.makedirs(log_directory, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration."""
        log_file = os.path.join(self.log_directory, f"dfw_{datetime.now().strftime('%Y%m%d')}.log")
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Setup logger
        self.logger = logging.getLogger('DFW')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
    def handle_exception(self, exc_type, exc_value, exc_traceback, 
                        user_message: str = None, show_dialog: bool = True):
        """Handle exceptions with logging and user notification.
        
        Args:
            exc_type: Exception type
            exc_value: Exception value
            exc_traceback: Exception traceback
            user_message: Custom message to show to user
            show_dialog: Whether to show error dialog to user
        """
        # Log the full exception
        error_msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        self.logger.error(f"Unhandled exception: {error_msg}")
        
        # Show user-friendly message
        if show_dialog:
            if user_message is None:
                user_message = f"An unexpected error occurred: {str(exc_value)}"
            
            messagebox.showerror("Error", user_message)
    
    def log_error(self, message: str, exception: Exception = None):
        """Log an error message.
        
        Args:
            message: Error message
            exception: Optional exception object
        """
        if exception:
            self.logger.error(f"{message}: {str(exception)}", exc_info=True)
        else:
            self.logger.error(message)
    
    def log_warning(self, message: str):
        """Log a warning message.
        
        Args:
            message: Warning message
        """
        self.logger.warning(message)
    
    def log_info(self, message: str):
        """Log an info message.
        
        Args:
            message: Info message
        """
        self.logger.info(message)
    
    def safe_execute(self, func: Callable, *args, 
                    error_message: str = None, 
                    default_return: Any = None,
                    show_error: bool = True, **kwargs):
        """Safely execute a function with error handling.
        
        Args:
            func: Function to execute
            *args: Function arguments
            error_message: Custom error message
            default_return: Value to return on error
            show_error: Whether to show error to user
            **kwargs: Function keyword arguments
            
        Returns:
            Function result or default_return on error
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if error_message is None:
                error_message = f"Error executing {func.__name__}: {str(e)}"
            
            self.log_error(error_message, e)
            
            if show_error:
                messagebox.showerror("Error", error_message)
            
            return default_return


def error_handler(error_message: str = None, 
                 default_return: Any = None,
                 show_error: bool = True,
                 log_error: bool = True):
    """Decorator for automatic error handling.
    
    Args:
        error_message: Custom error message
        default_return: Value to return on error
        show_error: Whether to show error dialog
        log_error: Whether to log the error
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Get error handler instance (assumes it's available globally)
                handler = getattr(sys.modules[func.__module__], 'error_handler_instance', None)
                
                msg = error_message or f"Error in {func.__name__}: {str(e)}"
                
                if log_error and handler:
                    handler.log_error(msg, e)
                elif log_error:
                    print(f"ERROR: {msg}")
                
                if show_error:
                    messagebox.showerror("Error", msg)
                
                return default_return
        return wrapper
    return decorator


def validate_input(value: Any, 
                  value_type: type = None,
                  min_length: int = None,
                  max_length: int = None,
                  not_empty: bool = False,
                  custom_validator: Callable = None) -> tuple[bool, str]:
    """Validate input with comprehensive checks.
    
    Args:
        value: Value to validate
        value_type: Expected type
        min_length: Minimum length for strings/lists
        max_length: Maximum length for strings/lists
        not_empty: Whether value should not be empty
        custom_validator: Custom validation function
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Type validation
        if value_type and not isinstance(value, value_type):
            return False, f"Expected {value_type.__name__}, got {type(value).__name__}"
        
        # Empty check
        if not_empty:
            if value is None or (hasattr(value, '__len__') and len(value) == 0):
                return False, "Value cannot be empty"
        
        # Length validation for strings and sequences
        if hasattr(value, '__len__'):
            length = len(value)
            if min_length is not None and length < min_length:
                return False, f"Minimum length is {min_length}, got {length}"
            if max_length is not None and length > max_length:
                return False, f"Maximum length is {max_length}, got {length}"
        
        # Custom validation
        if custom_validator:
            is_valid, message = custom_validator(value)
            if not is_valid:
                return False, message
        
        return True, ""
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def safe_file_operation(operation: str, file_path: str, 
                       check_exists: bool = True,
                       check_permissions: bool = True) -> tuple[bool, str]:
    """Safely validate file operations.
    
    Args:
        operation: Type of operation ('read', 'write', 'delete')
        file_path: Path to file
        check_exists: Whether to check if file exists
        check_permissions: Whether to check permissions
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        if not file_path:
            return False, "File path cannot be empty"
        
        # Check if file exists
        if check_exists and operation in ['read', 'delete']:
            if not os.path.exists(file_path):
                return False, f"File does not exist: {file_path}"
        
        # Check permissions
        if check_permissions:
            if operation == 'read' and not os.access(file_path, os.R_OK):
                return False, f"No read permission for: {file_path}"
            elif operation == 'write':
                # Check write permission on directory
                directory = os.path.dirname(file_path)
                if not os.access(directory, os.W_OK):
                    return False, f"No write permission for directory: {directory}"
            elif operation == 'delete' and not os.access(file_path, os.W_OK):
                return False, f"No delete permission for: {file_path}"
        
        return True, ""
        
    except Exception as e:
        return False, f"File validation error: {str(e)}"


# Global error handler instance
error_handler_instance = DFWErrorHandler()


def setup_global_exception_handler():
    """Setup global exception handler for unhandled exceptions."""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        error_handler_instance.handle_exception(
            exc_type, exc_value, exc_traceback,
            "An unexpected error occurred. Please check the log files for details."
        )
    
    sys.excepthook = handle_exception

