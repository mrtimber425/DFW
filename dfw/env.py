"""Environment detection utilities for the Digital Forensics Workbench.

This module provides helper functions to gather information about
the host operating system and determine the availability of various
command‑line tools used throughout the project. By centralising
environment checks here we avoid duplicating logic in the GUI layer
and can easily extend the list of tools in the future.

Functions:
    check_environment() -> dict
        Returns a dictionary describing the current OS and the
        presence of key forensic tools on the PATH.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Dict, Any


def _command_exists(cmd: str) -> bool:
    """Return True if the given command exists on the current PATH.

    Uses shutil.which to resolve the command name and returns
    True if a valid executable is found. This helper is extracted
    for readability.

    Args:
        cmd: Name of the command to check (e.g. ``"mmls"``).

    Returns:
        True if the command can be resolved, False otherwise.
    """
    return shutil.which(cmd) is not None


def _detect_wsl() -> bool:
    """Detect whether the current environment is running under Windows Subsystem for Linux.

    WSL exposes information through ``/proc/version`` on Linux that
    contains the string ``"Microsoft"``. This helper attempts to read
    that file and checks for the presence of the expected marker.

    Returns:
        True if running under WSL, False otherwise.
    """
    if platform.system().lower() != "linux":
        return False
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except Exception:
        return False


def check_environment() -> Dict[str, Any]:
    """Gather and return environment information relevant to digital forensics.

    The returned dictionary includes the host OS type, version, whether
    the process is running under Windows Subsystem for Linux, and a
    mapping of tool names to booleans indicating their availability on
    the PATH. The list of tools checked here can be expanded as
    additional integrations are added to the workbench. Only tools
    commonly used in digital forensics are included by default.

    Returns:
        A dictionary with keys ``"os_type"``, ``"os_version"``,
        ``"is_wsl"`` and ``"tools"``. ``tools`` itself is a
        dictionary mapping command names to True/False.
    """
    os_type = platform.system()
    os_version = platform.version() if os_type == "Windows" else platform.release()
    is_wsl = _detect_wsl()
    # Extend this list to include additional forensic tools as needed
    # List of external tools that may be used by the workbench.  The
    # names correspond to the executables that must be available on
    # your system PATH.  Adjust this list as new integrations are
    # added.  Note that Plaso is provided via the log2timeline.py
    # script rather than the older ``plaso`` wrapper, so we check
    # for ``log2timeline.py`` here.  Similarly ALEAPP exposes the
    # ``aleapp`` console script when installed via pip.
    tool_names = [
        "mmls",        # Sleuth Kit partition table listing
        "mount",       # Linux mount command
        "tshark",      # Network analysis from Wireshark
        "volatility3", # Memory analysis
        # Timeline functionality is now implemented internally, so no external
        # timeline generator is checked here.  You may still want to
        # install and use tools such as fls/mactime from The Sleuth Kit for
        # advanced timelines.
        "adb",         # Android Debug Bridge
        "aleapp",      # Android artefact parser
        "pytsk3"       # Python binding for The Sleuth Kit (checked via import)
    ]
    tools: Dict[str, bool] = {}
    # We check the availability of all tools except ``pytsk3`` with
    # shutil.which.  For pytsk3 the Python import mechanism is used
    # instead because it is a module rather than a command-line
    # executable.  Each entry in the resulting dictionary uses
    # the same key as ``tool_names``.  See the docstring for
    # additional details.
    for cmd in tool_names:
        if cmd == "pytsk3":
            try:
                import pytsk3  # type: ignore  # noqa: F401
                tools[cmd] = True
            except Exception:
                tools[cmd] = False
        else:
            tools[cmd] = _command_exists(cmd)
    return {
        "os_type": os_type,
        "os_version": os_version,
        "is_wsl": is_wsl,
        "tools": tools,
    }