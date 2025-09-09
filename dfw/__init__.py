# File: dfw/__init__.py
"""Digital Forensics Workbench - Professional Edition.

A comprehensive digital forensics analysis platform integrating
industry-standard tools with a modern GUI interface.
"""

__version__ = "3.0.0"
__author__ = "Mr.T"

# Import all modules
from . import (
    env,
    mount,
    keywords,
    forensic_tools,
    os_detector,
    browser_forensics,
    registry_analyzer,
    tool_manager,
    notes_terminal
)

# Main application
from .main_app import CompleteDFW, main

__all__ = [
    'env',
    'mount', 
    'keywords',
    'forensic_tools',
    'os_detector',
    'browser_forensics',
    'registry_analyzer',
    'tool_manager',
    'notes_terminal',
    'CompleteDFW',
    'main'
]
