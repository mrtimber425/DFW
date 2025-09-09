"""Utility functions for DFW."""

import os
import hashlib
import datetime
import subprocess
import platform
from pathlib import Path
from typing import Optional, List, Dict, Any


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate file hash.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)

    Returns:
        Hex digest of hash
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


def format_bytes(size: int) -> str:
    """Format byte size to human readable.

    Args:
        size: Size in bytes

    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def run_command(command: List[str], timeout: int = None) -> Dict[str, Any]:
    """Run external command.

    Args:
        command: Command and arguments
        timeout: Timeout in seconds

    Returns:
        Dictionary with stdout, stderr, and return code
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'return_code': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'stdout': '',
            'stderr': 'Command timed out',
            'return_code': -1
        }
    except Exception as e:
        return {
            'success': False,
            'stdout': '',
            'stderr': str(e),
            'return_code': -1
        }


def is_admin() -> bool:
    """Check if running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def ensure_directory(path: str) -> bool:
    """Ensure directory exists.

    Args:
        path: Directory path

    Returns:
        True if directory exists or was created
    """
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """Get file metadata.

    Args:
        file_path: Path to file

    Returns:
        Dictionary with file metadata
    """
    try:
        stat = os.stat(file_path)
        return {
            'size': stat.st_size,
            'created': datetime.datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
            'accessed': datetime.datetime.fromtimestamp(stat.st_atime),
            'mode': oct(stat.st_mode),
            'uid': stat.st_uid if hasattr(stat, 'st_uid') else None,
            'gid': stat.st_gid if hasattr(stat, 'st_gid') else None
        }
    except Exception as e:
        return {'error': str(e)}


def find_files(directory: str, pattern: str = "*",
               recursive: bool = True) -> List[str]:
    """Find files matching pattern.

    Args:
        directory: Directory to search
        pattern: File pattern (glob)
        recursive: Search recursively

    Returns:
        List of file paths
    """
    path = Path(directory)

    if recursive:
        return [str(f) for f in path.rglob(pattern) if f.is_file()]
    else:
        return [str(f) for f in path.glob(pattern) if f.is_file()]


def export_to_csv(data: List[Dict], output_file: str) -> bool:
    """Export data to CSV file.

    Args:
        data: List of dictionaries
        output_file: Output CSV file path

    Returns:
        True if successful
    """
    import csv

    try:
        if not data:
            return False

        keys = data[0].keys()

        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)

        return True
    except Exception:
        return False


def export_to_json(data: Any, output_file: str) -> bool:
    """Export data to JSON file.

    Args:
        data: Data to export
        output_file: Output JSON file path

    Returns:
        True if successful
    """
    import json

    try:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False