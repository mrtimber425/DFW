"""Browser forensics module for extracting and analyzing web browser artifacts.

This module provides comprehensive browser forensics capabilities for Chrome,
Firefox, Edge, Safari, and other browsers. It extracts history, cookies,
downloads, bookmarks, and other artifacts from browser databases.
"""

import os
import sqlite3
import json
import shutil
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import base64
import struct


@dataclass
class BrowserArtifact:
    """Generic browser artifact container."""
    artifact_type: str  # history, cookie, download, bookmark, etc.
    url: Optional[str] = None
    title: Optional[str] = None
    timestamp: Optional[datetime] = None
    data: Dict[str, Any] = None
    source_browser: Optional[str] = None
    source_file: Optional[str] = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}


class BrowserForensics:
    """Main browser forensics analyzer."""

    def __init__(self, mount_point: str):
        """Initialize browser forensics with mount point.

        Args:
            mount_point: Path to mounted filesystem or extracted directory
        """
        self.mount_point = mount_point
        self.artifacts = []
        self.temp_dir = tempfile.mkdtemp(prefix="browser_forensics_")

    def __del__(self):
        """Cleanup temporary directory."""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def analyze_all_browsers(self) -> List[BrowserArtifact]:
        """Analyze all browsers found on the system.

        Returns:
            List of all browser artifacts found
        """
        self.artifacts = []

        # Detect OS type to determine browser locations
        browser_analyzers = [
            self._analyze_chrome,
            self._analyze_firefox,
            self._analyze_edge,
            self._analyze_safari,
            self._analyze_opera,
            self._analyze_brave,
        ]

        for analyzer in browser_analyzers:
            try:
                analyzer()
            except Exception as e:
                print(f"Error in {analyzer.__name__}: {e}")

        return self.artifacts

    def _get_user_directories(self) -> List[str]:
        """Get all user directories based on OS."""
        user_dirs = []

        # Windows paths
        windows_users = os.path.join(self.mount_point, "Users")
        if os.path.exists(windows_users):
            for user in os.listdir(windows_users):
                user_path = os.path.join(windows_users, user)
                if os.path.isdir(user_path) and user not in ["Default", "Public", "All Users"]:
                    user_dirs.append(user_path)

        # Linux paths
        linux_home = os.path.join(self.mount_point, "home")
        if os.path.exists(linux_home):
            for user in os.listdir(linux_home):
                user_path = os.path.join(linux_home, user)
                if os.path.isdir(user_path):
                    user_dirs.append(user_path)

        # macOS paths
        macos_users = os.path.join(self.mount_point, "Users")
        if os.path.exists(macos_users):
            for user in os.listdir(macos_users):
                user_path = os.path.join(macos_users, user)
                if os.path.isdir(user_path) and user not in ["Shared", "Guest"]:
                    user_dirs.append(user_path)

        return user_dirs

    def _analyze_chrome(self) -> None:
        """Analyze Chrome/Chromium browser artifacts."""
        chrome_paths = []

        for user_dir in self._get_user_directories():
            # Windows Chrome paths
            chrome_paths.extend([
                os.path.join(user_dir, "AppData", "Local", "Google", "Chrome", "User Data"),
                os.path.join(user_dir, "AppData", "Local", "Chromium", "User Data"),
                # Linux Chrome paths
                os.path.join(user_dir, ".config", "google-chrome"),
                os.path.join(user_dir, ".config", "chromium"),
                # macOS Chrome paths
                os.path.join(user_dir, "Library", "Application Support", "Google", "Chrome"),
            ])

        for chrome_path in chrome_paths:
            if os.path.exists(chrome_path):
                self._process_chrome_profile(chrome_path)

    def _process_chrome_profile(self, profile_path: str) -> None:
        """Process Chrome profile directory."""
        # Process Default profile and numbered profiles
        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]

        for profile in profiles:
            profile_dir = os.path.join(profile_path, profile)
            if not os.path.exists(profile_dir):
                continue

            # Extract history
            history_db = os.path.join(profile_dir, "History")
            if os.path.exists(history_db):
                self._extract_chrome_history(history_db)

            # Extract downloads
            self._extract_chrome_downloads(history_db)

            # Extract cookies
            cookies_db = os.path.join(profile_dir, "Cookies")
            if os.path.exists(cookies_db):
                self._extract_chrome_cookies(cookies_db)

            # Extract bookmarks
            bookmarks_file = os.path.join(profile_dir, "Bookmarks")
            if os.path.exists(bookmarks_file):
                self._extract_chrome_bookmarks(bookmarks_file)

            # Extract login data
            login_db = os.path.join(profile_dir, "Login Data")
            if os.path.exists(login_db):
                self._extract_chrome_logins(login_db)

            # Extract autofill data
            self._extract_chrome_autofill(history_db)

    def _extract_chrome_history(self, db_path: str) -> None:
        """Extract Chrome browsing history."""
        try:
            # Copy database to temp location to avoid locks
            temp_db = os.path.join(self.temp_dir, "chrome_history.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Query history
            query = """
                SELECT url, title, visit_count, last_visit_time, 
                       typed_count, hidden
                FROM urls
                ORDER BY last_visit_time DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                url, title, visit_count, last_visit, typed_count, hidden = row

                # Convert Chrome timestamp (microseconds since 1601)
                timestamp = self._chrome_timestamp_to_datetime(last_visit)

                artifact = BrowserArtifact(
                    artifact_type="history",
                    url=url,
                    title=title,
                    timestamp=timestamp,
                    data={
                        "visit_count": visit_count,
                        "typed_count": typed_count,
                        "hidden": bool(hidden),
                    },
                    source_browser="Chrome",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Chrome history: {e}")

    def _extract_chrome_downloads(self, db_path: str) -> None:
        """Extract Chrome download history."""
        try:
            temp_db = os.path.join(self.temp_dir, "chrome_downloads.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT target_path, tab_url, start_time, end_time,
                       received_bytes, total_bytes, state, danger_type,
                       interrupt_reason, mime_type, original_mime_type
                FROM downloads
                ORDER BY start_time DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                (target_path, tab_url, start_time, end_time, received_bytes,
                 total_bytes, state, danger_type, interrupt_reason,
                 mime_type, original_mime_type) = row

                timestamp = self._chrome_timestamp_to_datetime(start_time)

                artifact = BrowserArtifact(
                    artifact_type="download",
                    url=tab_url,
                    title=os.path.basename(target_path) if target_path else None,
                    timestamp=timestamp,
                    data={
                        "target_path": target_path,
                        "received_bytes": received_bytes,
                        "total_bytes": total_bytes,
                        "state": state,
                        "danger_type": danger_type,
                        "interrupt_reason": interrupt_reason,
                        "mime_type": mime_type,
                        "completed": state == 1,
                    },
                    source_browser="Chrome",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Chrome downloads: {e}")

    def _extract_chrome_cookies(self, db_path: str) -> None:
        """Extract Chrome cookies."""
        try:
            temp_db = os.path.join(self.temp_dir, "chrome_cookies.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT host_key, name, value, path, expires_utc,
                       is_secure, is_httponly, last_access_utc,
                       has_expires, is_persistent
                FROM cookies
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                (host_key, name, value, path, expires_utc, is_secure,
                 is_httponly, last_access, has_expires, is_persistent) = row

                timestamp = self._chrome_timestamp_to_datetime(last_access)

                artifact = BrowserArtifact(
                    artifact_type="cookie",
                    url=host_key,
                    title=name,
                    timestamp=timestamp,
                    data={
                        "path": path,
                        "expires": self._chrome_timestamp_to_datetime(expires_utc) if expires_utc else None,
                        "secure": bool(is_secure),
                        "httponly": bool(is_httponly),
                        "persistent": bool(is_persistent),
                        "value_encrypted": True,  # Chrome encrypts cookie values
                    },
                    source_browser="Chrome",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Chrome cookies: {e}")

    def _extract_chrome_bookmarks(self, bookmarks_path: str) -> None:
        """Extract Chrome bookmarks from JSON file."""
        try:
            with open(bookmarks_path, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)

            def process_bookmark_node(node, parent_folder=""):
                """Recursively process bookmark nodes."""
                if node.get('type') == 'url':
                    # It's a bookmark
                    artifact = BrowserArtifact(
                        artifact_type="bookmark",
                        url=node.get('url'),
                        title=node.get('name'),
                        timestamp=self._chrome_timestamp_to_datetime(
                            int(node.get('date_added', 0))
                        ),
                        data={
                            "folder": parent_folder,
                            "id": node.get('id'),
                        },
                        source_browser="Chrome",
                        source_file=bookmarks_path
                    )
                    self.artifacts.append(artifact)
                elif node.get('type') == 'folder':
                    # It's a folder, process children
                    folder_name = node.get('name', '')
                    if parent_folder:
                        folder_path = f"{parent_folder}/{folder_name}"
                    else:
                        folder_path = folder_name

                    for child in node.get('children', []):
                        process_bookmark_node(child, folder_path)

            # Process bookmark bar and other bookmarks
            roots = bookmarks_data.get('roots', {})
            for root_name, root_node in roots.items():
                if isinstance(root_node, dict) and 'children' in root_node:
                    for child in root_node['children']:
                        process_bookmark_node(child, root_name)

        except Exception as e:
            print(f"Error extracting Chrome bookmarks: {e}")

    def _extract_chrome_logins(self, db_path: str) -> None:
        """Extract Chrome saved login data (URLs and usernames only)."""
        try:
            temp_db = os.path.join(self.temp_dir, "chrome_logins.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT origin_url, username_value, date_created,
                       times_used, date_last_used
                FROM logins
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                url, username, date_created, times_used, date_last_used = row

                timestamp = self._chrome_timestamp_to_datetime(date_created)

                artifact = BrowserArtifact(
                    artifact_type="saved_login",
                    url=url,
                    title=username,
                    timestamp=timestamp,
                    data={
                        "username": username,
                        "times_used": times_used,
                        "last_used": self._chrome_timestamp_to_datetime(date_last_used),
                        "password_encrypted": True,
                    },
                    source_browser="Chrome",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Chrome logins: {e}")

    def _extract_chrome_autofill(self, db_path: str) -> None:
        """Extract Chrome autofill data."""
        try:
            temp_db = os.path.join(self.temp_dir, "chrome_autofill.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Extract autofill entries
            query = """
                SELECT name, value, count, date_created, date_last_used
                FROM autofill
                ORDER BY count DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                name, value, count, date_created, date_last_used = row

                artifact = BrowserArtifact(
                    artifact_type="autofill",
                    title=name,
                    timestamp=self._chrome_timestamp_to_datetime(date_created),
                    data={
                        "field_name": name,
                        "value": value,
                        "use_count": count,
                        "last_used": self._chrome_timestamp_to_datetime(date_last_used),
                    },
                    source_browser="Chrome",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Chrome autofill: {e}")

    def _analyze_firefox(self) -> None:
        """Analyze Firefox browser artifacts."""
        firefox_paths = []

        for user_dir in self._get_user_directories():
            # Windows Firefox paths
            firefox_paths.extend([
                os.path.join(user_dir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
                # Linux Firefox paths
                os.path.join(user_dir, ".mozilla", "firefox"),
                # macOS Firefox paths
                os.path.join(user_dir, "Library", "Application Support", "Firefox", "Profiles"),
            ])

        for firefox_path in firefox_paths:
            if os.path.exists(firefox_path):
                self._process_firefox_profiles(firefox_path)

    def _process_firefox_profiles(self, profiles_path: str) -> None:
        """Process Firefox profile directories."""
        try:
            for profile_dir in os.listdir(profiles_path):
                profile_path = os.path.join(profiles_path, profile_dir)
                if not os.path.isdir(profile_path):
                    continue

                # Extract history and downloads
                places_db = os.path.join(profile_path, "places.sqlite")
                if os.path.exists(places_db):
                    self._extract_firefox_history(places_db)
                    self._extract_firefox_bookmarks(places_db)
                    self._extract_firefox_downloads(places_db)

                # Extract cookies
                cookies_db = os.path.join(profile_path, "cookies.sqlite")
                if os.path.exists(cookies_db):
                    self._extract_firefox_cookies(cookies_db)

                # Extract form history
                formhistory_db = os.path.join(profile_path, "formhistory.sqlite")
                if os.path.exists(formhistory_db):
                    self._extract_firefox_formhistory(formhistory_db)

                # Extract logins
                logins_json = os.path.join(profile_path, "logins.json")
                if os.path.exists(logins_json):
                    self._extract_firefox_logins(logins_json)

        except Exception as e:
            print(f"Error processing Firefox profiles: {e}")

    def _extract_firefox_history(self, db_path: str) -> None:
        """Extract Firefox browsing history."""
        try:
            temp_db = os.path.join(self.temp_dir, "firefox_history.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT url, title, visit_count, typed, last_visit_date,
                       frecency
                FROM moz_places
                WHERE visit_count > 0
                ORDER BY last_visit_date DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                url, title, visit_count, typed, last_visit, frecency = row

                # Convert Firefox timestamp (microseconds since epoch)
                timestamp = datetime.fromtimestamp(last_visit / 1000000) if last_visit else None

                artifact = BrowserArtifact(
                    artifact_type="history",
                    url=url,
                    title=title,
                    timestamp=timestamp,
                    data={
                        "visit_count": visit_count,
                        "typed": typed,
                        "frecency": frecency,
                    },
                    source_browser="Firefox",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Firefox history: {e}")

    def _extract_firefox_bookmarks(self, db_path: str) -> None:
        """Extract Firefox bookmarks."""
        try:
            temp_db = os.path.join(self.temp_dir, "firefox_bookmarks.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT b.title, p.url, b.dateAdded
                FROM moz_bookmarks b
                JOIN moz_places p ON b.fk = p.id
                WHERE b.type = 1
                ORDER BY b.dateAdded DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                title, url, date_added = row

                timestamp = datetime.fromtimestamp(date_added / 1000000) if date_added else None

                artifact = BrowserArtifact(
                    artifact_type="bookmark",
                    url=url,
                    title=title,
                    timestamp=timestamp,
                    source_browser="Firefox",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Firefox bookmarks: {e}")

    def _extract_firefox_downloads(self, db_path: str) -> None:
        """Extract Firefox download history."""
        try:
            temp_db = os.path.join(self.temp_dir, "firefox_downloads.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Firefox stores download info in moz_annos table
            query = """
                SELECT p.url, a.content, a.dateAdded
                FROM moz_annos a
                JOIN moz_places p ON a.place_id = p.id
                WHERE a.anno_attribute_id = (
                    SELECT id FROM moz_anno_attributes 
                    WHERE name = 'downloads/destinationFileURI'
                )
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                url, destination, date_added = row

                timestamp = datetime.fromtimestamp(date_added / 1000000) if date_added else None

                artifact = BrowserArtifact(
                    artifact_type="download",
                    url=url,
                    title=os.path.basename(destination) if destination else None,
                    timestamp=timestamp,
                    data={
                        "destination": destination,
                    },
                    source_browser="Firefox",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Firefox downloads: {e}")

    def _extract_firefox_cookies(self, db_path: str) -> None:
        """Extract Firefox cookies."""
        try:
            temp_db = os.path.join(self.temp_dir, "firefox_cookies.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT host, name, value, path, expiry, lastAccessed,
                       isSecure, isHttpOnly
                FROM moz_cookies
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                (host, name, value, path, expiry, last_accessed,
                 is_secure, is_httponly) = row

                timestamp = datetime.fromtimestamp(last_accessed / 1000000) if last_accessed else None

                artifact = BrowserArtifact(
                    artifact_type="cookie",
                    url=host,
                    title=name,
                    timestamp=timestamp,
                    data={
                        "value": value,
                        "path": path,
                        "expires": datetime.fromtimestamp(expiry) if expiry else None,
                        "secure": bool(is_secure),
                        "httponly": bool(is_httponly),
                    },
                    source_browser="Firefox",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Firefox cookies: {e}")

    def _extract_firefox_formhistory(self, db_path: str) -> None:
        """Extract Firefox form history."""
        try:
            temp_db = os.path.join(self.temp_dir, "firefox_formhistory.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory
                ORDER BY timesUsed DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                fieldname, value, times_used, first_used, last_used = row

                timestamp = datetime.fromtimestamp(last_used / 1000000) if last_used else None

                artifact = BrowserArtifact(
                    artifact_type="form_history",
                    title=fieldname,
                    timestamp=timestamp,
                    data={
                        "field_name": fieldname,
                        "value": value,
                        "times_used": times_used,
                        "first_used": datetime.fromtimestamp(first_used / 1000000) if first_used else None,
                    },
                    source_browser="Firefox",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Firefox form history: {e}")

    def _extract_firefox_logins(self, logins_path: str) -> None:
        """Extract Firefox saved logins from JSON file."""
        try:
            with open(logins_path, 'r', encoding='utf-8') as f:
                logins_data = json.load(f)

            for login in logins_data.get('logins', []):
                artifact = BrowserArtifact(
                    artifact_type="saved_login",
                    url=login.get('hostname'),
                    title=login.get('username'),
                    timestamp=datetime.fromtimestamp(
                        login.get('timeCreated', 0) / 1000
                    ) if login.get('timeCreated') else None,
                    data={
                        "username": login.get('username'),
                        "password_encrypted": True,
                        "times_used": login.get('timesUsed'),
                        "last_used": datetime.fromtimestamp(
                            login.get('timeLastUsed', 0) / 1000
                        ) if login.get('timeLastUsed') else None,
                    },
                    source_browser="Firefox",
                    source_file=logins_path
                )
                self.artifacts.append(artifact)

        except Exception as e:
            print(f"Error extracting Firefox logins: {e}")

    def _analyze_edge(self) -> None:
        """Analyze Microsoft Edge browser artifacts."""
        # Edge uses the same Chromium base as Chrome
        edge_paths = []

        for user_dir in self._get_user_directories():
            # Windows Edge paths
            edge_paths.extend([
                os.path.join(user_dir, "AppData", "Local", "Microsoft", "Edge", "User Data"),
                # macOS Edge paths
                os.path.join(user_dir, "Library", "Application Support", "Microsoft Edge"),
            ])

        for edge_path in edge_paths:
            if os.path.exists(edge_path):
                self._process_edge_profile(edge_path)

    def _process_edge_profile(self, profile_path: str) -> None:
        """Process Edge profile (similar to Chrome)."""
        # Edge uses the same database structure as Chrome
        # Reuse Chrome extraction methods with Edge label
        profiles = ["Default"] + [f"Profile {i}" for i in range(1, 10)]

        for profile in profiles:
            profile_dir = os.path.join(profile_path, profile)
            if not os.path.exists(profile_dir):
                continue

            # Extract history
            history_db = os.path.join(profile_dir, "History")
            if os.path.exists(history_db):
                # Temporarily change browser name for artifacts
                original_artifacts_len = len(self.artifacts)
                self._extract_chrome_history(history_db)
                # Update browser name for newly added artifacts
                for artifact in self.artifacts[original_artifacts_len:]:
                    artifact.source_browser = "Edge"

    def _analyze_safari(self) -> None:
        """Analyze Safari browser artifacts (macOS)."""
        safari_paths = []

        for user_dir in self._get_user_directories():
            safari_paths.append(
                os.path.join(user_dir, "Library", "Safari")
            )

        for safari_path in safari_paths:
            if os.path.exists(safari_path):
                self._process_safari_profile(safari_path)

    def _process_safari_profile(self, safari_path: str) -> None:
        """Process Safari browser data."""
        # Safari history
        history_db = os.path.join(safari_path, "History.db")
        if os.path.exists(history_db):
            self._extract_safari_history(history_db)

        # Safari bookmarks
        bookmarks_plist = os.path.join(safari_path, "Bookmarks.plist")
        if os.path.exists(bookmarks_plist):
            # Note: plist parsing requires additional library
            pass

    def _extract_safari_history(self, db_path: str) -> None:
        """Extract Safari browsing history."""
        try:
            temp_db = os.path.join(self.temp_dir, "safari_history.db")
            shutil.copy2(db_path, temp_db)

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            query = """
                SELECT url, title, visit_count, 
                       datetime(visit_time + 978307200, 'unixepoch')
                FROM history_items
                ORDER BY visit_time DESC
            """

            cursor.execute(query)
            for row in cursor.fetchall():
                url, title, visit_count, visit_time = row

                artifact = BrowserArtifact(
                    artifact_type="history",
                    url=url,
                    title=title,
                    timestamp=datetime.strptime(visit_time, "%Y-%m-%d %H:%M:%S") if visit_time else None,
                    data={
                        "visit_count": visit_count,
                    },
                    source_browser="Safari",
                    source_file=db_path
                )
                self.artifacts.append(artifact)

            conn.close()
        except Exception as e:
            print(f"Error extracting Safari history: {e}")

    def _analyze_opera(self) -> None:
        """Analyze Opera browser artifacts."""
        # Opera also uses Chromium base
        opera_paths = []

        for user_dir in self._get_user_directories():
            opera_paths.extend([
                os.path.join(user_dir, "AppData", "Roaming", "Opera Software", "Opera Stable"),
                os.path.join(user_dir, ".config", "opera"),
            ])

        for opera_path in opera_paths:
            if os.path.exists(opera_path):
                # Use Chrome extraction methods with Opera label
                pass

    def _analyze_brave(self) -> None:
        """Analyze Brave browser artifacts."""
        # Brave also uses Chromium base
        brave_paths = []

        for user_dir in self._get_user_directories():
            brave_paths.extend([
                os.path.join(user_dir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
                os.path.join(user_dir, ".config", "BraveSoftware", "Brave-Browser"),
            ])

        for brave_path in brave_paths:
            if os.path.exists(brave_path):
                # Use Chrome extraction methods with Brave label
                pass

    def _chrome_timestamp_to_datetime(self, chrome_timestamp: int) -> Optional[datetime]:
        """Convert Chrome timestamp to datetime.

        Chrome timestamps are microseconds since January 1, 1601 UTC
        """
        if not chrome_timestamp:
            return None
        try:
            # Convert to Unix timestamp
            unix_timestamp = (chrome_timestamp - 11644473600000000) / 1000000
            return datetime.fromtimestamp(unix_timestamp)
        except:
            return None

    def export_artifacts(self, output_format: str = "json") -> str:
        """Export artifacts to various formats.

        Args:
            output_format: Format to export (json, csv, html)

        Returns:
            Exported data as string
        """
        if output_format == "json":
            return self._export_json()
        elif output_format == "csv":
            return self._export_csv()
        elif output_format == "html":
            return self._export_html()
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _export_json(self) -> str:
        """Export artifacts as JSON."""
        export_data = []
        for artifact in self.artifacts:
            export_data.append({
                "type": artifact.artifact_type,
                "url": artifact.url,
                "title": artifact.title,
                "timestamp": artifact.timestamp.isoformat() if artifact.timestamp else None,
                "browser": artifact.source_browser,
                "data": artifact.data,
            })
        return json.dumps(export_data, indent=2, default=str)

    def _export_csv(self) -> str:
        """Export artifacts as CSV."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "Type", "URL", "Title", "Timestamp", "Browser", "Additional Data"
        ])

        # Data rows
        for artifact in self.artifacts:
            writer.writerow([
                artifact.artifact_type,
                artifact.url,
                artifact.title,
                artifact.timestamp.isoformat() if artifact.timestamp else "",
                artifact.source_browser,
                json.dumps(artifact.data, default=str),
            ])

        return output.getvalue()

    def _export_html(self) -> str:
        """Export artifacts as HTML report."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Browser Forensics Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Browser Forensics Report</h1>
    <p>Total artifacts found: {}</p>
    <table>
        <tr>
            <th>Type</th>
            <th>URL</th>
            <th>Title</th>
            <th>Timestamp</th>
            <th>Browser</th>
        </tr>
""".format(len(self.artifacts))

        for artifact in self.artifacts:
            html += f"""
        <tr>
            <td>{artifact.artifact_type}</td>
            <td>{artifact.url or ''}</td>
            <td>{artifact.title or ''}</td>
            <td>{artifact.timestamp.isoformat() if artifact.timestamp else ''}</td>
            <td>{artifact.source_browser}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""
        return html