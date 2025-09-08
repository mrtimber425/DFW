"""Wrappers around external forensic tools.

The functions in this module provide a thin interface on top of
common open source forensic utilities. Each function checks whether
the relevant tool is available before attempting to invoke it via
``subprocess.run``. If the tool is not installed an informative
exception is raised. Outputs are returned as plain text strings for
display in the GUI. Error messages from the child processes are
captured and returned when a command fails.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional, List, Tuple
import datetime


class ToolUnavailableError(Exception):
    """Raised when a required external tool is not installed."""


def _check_tool(tool: str) -> None:
    """Raise ToolUnavailableError if tool is not on the PATH."""
    if shutil.which(tool) is None:
        raise ToolUnavailableError(f"Required tool '{tool}' is not installed or not on PATH.")


def run_volatility(image_path: str, plugin: str, profile: Optional[str] = None, extra_args: Optional[list[str]] = None) -> str:
    """Run a Volatility3 plugin against a memory image and return its output.

    Args:
        image_path: Path to the memory image file (e.g. crash dump).
        plugin: Name of the Volatility3 plugin to run (e.g. ``"windows.pslist"``).
        profile: Optional OS profile or configuration (currently unused but reserved for future use).
        extra_args: Additional command line arguments to pass to Volatility3.

    Returns:
        The stdout from Volatility3 as a string. If the command fails,
        stderr is returned instead.
    """
    _check_tool('volatility3')
    cmd = ['volatility3', '-f', image_path, plugin]
    if extra_args:
        cmd.extend(extra_args)
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return completed.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr


def run_tshark(pcap_path: str, summary: bool = True) -> str:
    """Run tshark to analyse a PCAP file and return a textual summary.

    If ``summary`` is True the function invokes tshark with the
    ``-z io,phs`` option which produces per‐host statistics (bytes
    sent/received etc.). Otherwise the default packet summary is
    returned. The caller should ensure that tshark is installed
    (typically distributed with Wireshark).

    Args:
        pcap_path: Path to the PCAP or PCAPNG file.
        summary: Whether to generate per‑host statistics.

    Returns:
        The stdout from tshark as a string. If the command fails,
        stderr is returned instead.
    """
    _check_tool('tshark')
    if summary:
        cmd = ['tshark', '-r', pcap_path, '-q', '-z', 'io,phs']
    else:
        cmd = ['tshark', '-r', pcap_path]
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return completed.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr


def generate_file_timeline(root_path: str) -> str:
    """Generate a simple timeline based on file system metadata.

    This function walks the directory tree rooted at ``root_path`` and
    collects the access (A), modification (M) and creation/change (C)
    timestamps for each file. It returns a string where each line
    represents an event in the format ``ISO8601<TAB>EventType<TAB>Path``.
    Events are sorted chronologically.

    Args:
        root_path: Path to the directory to scan.

    Returns:
        A newline-delimited string of events. If an error occurs while
        accessing a file (e.g. due to permission errors), the file is
        skipped. The timestamps are converted to the system's local
        timezone.
    """
    events: List[Tuple[float, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            try:
                st = os.stat(path)
            except OSError:
                # Skip files we cannot stat
                continue
            # Note: On Windows st_ctime is creation time, on Unix it is
            # metadata change time. Both are still interesting for
            # timeline purposes.
            events.append((st.st_atime, 'A', path))
            events.append((st.st_mtime, 'M', path))
            events.append((st.st_ctime, 'C', path))
    # Sort by timestamp
    events.sort(key=lambda x: x[0])
    lines = []
    for ts, typ, path in events:
        dt = datetime.datetime.fromtimestamp(ts)
        # Format ISO8601 with timezone information if available
        try:
            # Python 3.9+: includes timezone
            lines.append(f"{dt.isoformat()}\t{typ}\t{path}")
        except Exception:
            lines.append(f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}\t{typ}\t{path}")
    return '\n'.join(lines)


def run_aleapp(input_path: str, output_dir: str) -> str:
    """Run ALEAPP (Android Logs Events And Protobuf Parser) against an Android data source.

    ALEAPP supports both logical and physical extractions. The ``input_path``
    should point to the root of the Android filesystem (e.g. an ADB
    backup or mounted image). The function writes reports to
    ``output_dir`` and returns the program output.

    Args:
        input_path: Path to the Android data directory or image.
        output_dir: Directory where ALEAPP will write its reports.

    Returns:
        The stdout from ALEAPP or stderr on failure.
    """
    # ALEAPP is typically installed via pip and exposes 'aleapp' command
    _check_tool('aleapp')
    os.makedirs(output_dir, exist_ok=True)
    cmd = ['aleapp', '-i', input_path, '-o', output_dir]
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return completed.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr