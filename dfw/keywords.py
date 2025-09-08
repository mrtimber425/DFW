"""Keyword search functionality for evidence directories.

This module provides a simple keyword search over a filesystem tree.
It scans text files and attempts to decode binary files to UTF‑8 to
locate occurrences of user‑provided keywords. The search is case
insensitive and returns a list of results containing the path to the
file, the matched keyword and a short snippet of surrounding context.

Note: Searching large images can be time‑consuming. In practice it
may be desirable to implement paging or limit scanning to a subset
of the filesystem. This implementation is intentionally simple to
illustrate the concept and can be extended as needed.
"""

from __future__ import annotations

import os
import re
from typing import List, Dict, Any, Optional


def _read_text_from_file(path: str, max_bytes: Optional[int] = None) -> Optional[str]:
    """Attempt to read the contents of a file and decode it as UTF‑8.

    If the file is larger than ``max_bytes`` then only the first
    ``max_bytes`` bytes will be read. This helps avoid loading very
    large files entirely into memory. If decoding fails the function
    returns None.

    Args:
        path: Path to the file on disk.
        max_bytes: Optional maximum number of bytes to read. If
            ``None`` the entire file is read.

    Returns:
        A decoded string if successful, otherwise None.
    """
    try:
        with open(path, 'rb') as f:
            data = f.read() if max_bytes is None else f.read(max_bytes)
        # Attempt to decode as UTF‑8; fall back to latin1 if needed
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('latin1', errors='ignore')
    except Exception:
        return None


def search_keywords(base_path: str, keywords: List[str], max_bytes: Optional[int] = 1048576) -> List[Dict[str, Any]]:
    """Search for keywords within files under a given directory.

    Recursively walks ``base_path`` and inspects each regular file. The
    file is read up to ``max_bytes`` bytes and scanned case
    insensitively for any of the provided keywords. When a match is
    found a result entry is appended containing the file path,
    matched keyword, and a context string showing up to 40 characters
    before and after the match. Files that cannot be decoded are
    silently skipped.

    Args:
        base_path: Root directory to search.
        keywords: List of keywords or phrases to search for. Keyword
            matching is case insensitive.
        max_bytes: Maximum number of bytes to read from each file
            during the search. Defaults to 1 MiB. Set to None to
            disable the limit.

    Returns:
        A list of dictionaries with keys ``file``, ``keyword`` and
        ``context`` describing each match found.
    """
    if not os.path.isdir(base_path):
        raise NotADirectoryError(f"Search base path is not a directory: {base_path}")
    # Prepare regular expression with all keywords joined by | for OR matching
    escaped = [re.escape(k) for k in keywords if k]
    if not escaped:
        return []
    pattern = re.compile('|'.join(escaped), flags=re.IGNORECASE)
    results: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(base_path):
        for fname in files:
            full_path = os.path.join(root, fname)
            text = _read_text_from_file(full_path, max_bytes)
            if text is None:
                continue
            for match in pattern.finditer(text):
                start = max(0, match.start() - 40)
                end = min(len(text), match.end() + 40)
                context = text[start:end]
                # Clean up newlines in context for display purposes
                context = context.replace('\n', ' ').replace('\r', '')
                results.append({
                    'file': full_path,
                    'keyword': match.group(0),
                    'context': context
                })
    return results