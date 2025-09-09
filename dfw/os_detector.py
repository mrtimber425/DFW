"""Automatic OS detection for mounted drives and disk images.

This module provides functionality to automatically detect the operating
system type of mounted drives or extracted filesystems. It uses various
heuristics and artifact patterns to identify Windows, Linux, macOS, Android,
and other operating systems.
"""

import os
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class OSType(Enum):
    """Enumeration of supported operating system types."""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    ANDROID = "Android"
    IOS = "iOS"
    FREEBSD = "FreeBSD"
    VMWARE_ESX = "VMware ESX"
    UNKNOWN = "Unknown"


@dataclass
class OSInfo:
    """Detailed information about detected operating system."""
    os_type: OSType
    version: Optional[str] = None
    architecture: Optional[str] = None
    hostname: Optional[str] = None
    install_date: Optional[str] = None
    last_boot: Optional[str] = None
    users: List[str] = None
    confidence: float = 0.0
    artifacts_found: List[str] = None

    def __post_init__(self):
        if self.users is None:
            self.users = []
        if self.artifacts_found is None:
            self.artifacts_found = []


class OSDetector:
    """Automatic operating system detection for forensic analysis."""

    def __init__(self, mount_point: str):
        """Initialize the OS detector with a mount point.

        Args:
            mount_point: Path to the mounted filesystem or extracted directory
        """
        self.mount_point = mount_point
        self.os_info = None

    def detect(self) -> OSInfo:
        """Perform OS detection and return detailed information.

        Returns:
            OSInfo object containing detected OS details
        """
        # Try each detection method in order of specificity
        detectors = [
            self._detect_windows,
            self._detect_linux,
            self._detect_android,
            self._detect_macos,
            self._detect_ios_backup,
            self._detect_freebsd,
            self._detect_vmware_esx,
        ]

        for detector in detectors:
            result = detector()
            if result and result.confidence > 0.5:
                self.os_info = result
                return result

        # If no specific OS detected, return unknown
        return OSInfo(os_type=OSType.UNKNOWN, confidence=0.0)

    def _detect_windows(self) -> Optional[OSInfo]:
        """Detect Windows operating system."""
        info = OSInfo(os_type=OSType.WINDOWS)
        confidence = 0.0
        artifacts = []

        # Check for Windows directory
        windows_dir = os.path.join(self.mount_point, "Windows")
        if os.path.exists(windows_dir):
            confidence += 0.3
            artifacts.append("Windows directory")

        # Check for key Windows subdirectories
        windows_subdirs = ["System32", "SysWOW64", "Boot", "Fonts"]
        for subdir in windows_subdirs:
            if os.path.exists(os.path.join(windows_dir, subdir)):
                confidence += 0.1
                artifacts.append(f"Windows/{subdir}")

        # Check for Program Files
        if os.path.exists(os.path.join(self.mount_point, "Program Files")):
            confidence += 0.2
            artifacts.append("Program Files")

        # Check for registry hives
        registry_path = os.path.join(windows_dir, "System32", "config")
        if os.path.exists(registry_path):
            hives = ["SAM", "SYSTEM", "SOFTWARE", "SECURITY"]
            for hive in hives:
                if os.path.exists(os.path.join(registry_path, hive)):
                    confidence += 0.05
                    artifacts.append(f"Registry hive: {hive}")

        # Try to detect Windows version
        version = self._detect_windows_version()
        if version:
            info.version = version
            confidence += 0.1

        # Check for Users directory
        users_dir = os.path.join(self.mount_point, "Users")
        if os.path.exists(users_dir):
            users = self._list_windows_users(users_dir)
            info.users = users
            if users:
                confidence += 0.1

        # Detect architecture
        if os.path.exists(os.path.join(self.mount_point, "Program Files (x86)")):
            info.architecture = "x64"
        else:
            info.architecture = "x86"

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _detect_windows_version(self) -> Optional[str]:
        """Detect specific Windows version from artifacts."""
        # Check for version file
        version_files = [
            os.path.join(self.mount_point, "Windows", "System32", "license.rtf"),
            os.path.join(self.mount_point, "Windows", "System32", "ntoskrnl.exe"),
        ]

        # Version detection based on specific files/folders
        version_indicators = {
            "Windows 11": ["Windows", "System32", "Windows.UI.Xaml.dll"],
            "Windows 10": ["Windows", "SystemApps"],
            "Windows 8.1": ["Windows", "ImmersiveControlPanel"],
            "Windows 8": ["Windows", "System32", "d3d11.dll"],
            "Windows 7": ["Windows", "System32", "explorerframe.dll"],
            "Windows Vista": ["Windows", "System32", "msctf.dll"],
            "Windows XP": ["Windows", "System32", "ntkrnlpa.exe"],
            "Windows Server 2022": ["Windows", "System32", "ServerManager.exe"],
            "Windows Server 2019": ["Windows", "System32", "config", "COMPONENTS"],
            "Windows Server 2016": ["Windows", "System32", "SecConfig.efi"],
        }

        for version, indicators in version_indicators.items():
            path = os.path.join(self.mount_point, *indicators)
            if os.path.exists(path):
                return version

        return None

    def _list_windows_users(self, users_dir: str) -> List[str]:
        """List Windows user accounts from Users directory."""
        users = []
        try:
            for item in os.listdir(users_dir):
                user_path = os.path.join(users_dir, item)
                if os.path.isdir(user_path):
                    # Skip system directories
                    if item not in ["Default", "Public", "All Users", "Default User"]:
                        users.append(item)
        except OSError:
            pass
        return users

    def _detect_linux(self) -> Optional[OSInfo]:
        """Detect Linux operating system."""
        info = OSInfo(os_type=OSType.LINUX)
        confidence = 0.0
        artifacts = []

        # Check for Linux root directories
        linux_dirs = ["etc", "var", "usr", "bin", "sbin", "lib", "boot"]
        for dir_name in linux_dirs:
            if os.path.exists(os.path.join(self.mount_point, dir_name)):
                confidence += 0.1
                artifacts.append(f"/{dir_name}")

        # Check for /etc/os-release (modern Linux)
        os_release = os.path.join(self.mount_point, "etc", "os-release")
        if os.path.exists(os_release):
            confidence += 0.3
            artifacts.append("/etc/os-release")
            distro_info = self._parse_os_release(os_release)
            if distro_info:
                info.version = distro_info.get("PRETTY_NAME", distro_info.get("NAME"))

        # Check for other distribution files
        distro_files = {
            "/etc/redhat-release": "RedHat/CentOS/Fedora",
            "/etc/debian_version": "Debian/Ubuntu",
            "/etc/SuSE-release": "SUSE",
            "/etc/arch-release": "Arch Linux",
            "/etc/gentoo-release": "Gentoo",
            "/etc/slackware-version": "Slackware",
        }

        for file_path, distro in distro_files.items():
            full_path = os.path.join(self.mount_point, file_path.lstrip('/'))
            if os.path.exists(full_path):
                confidence += 0.1
                artifacts.append(file_path)
                if not info.version:
                    info.version = distro

        # Check for systemd
        if os.path.exists(os.path.join(self.mount_point, "usr", "lib", "systemd")):
            confidence += 0.1
            artifacts.append("systemd")

        # List users from /etc/passwd
        passwd_file = os.path.join(self.mount_point, "etc", "passwd")
        if os.path.exists(passwd_file):
            users = self._parse_linux_users(passwd_file)
            info.users = users

        # Detect architecture from lib directories
        if os.path.exists(os.path.join(self.mount_point, "lib64")):
            info.architecture = "x86_64"
        elif os.path.exists(os.path.join(self.mount_point, "lib32")):
            info.architecture = "i386"

        # Check hostname
        hostname_file = os.path.join(self.mount_point, "etc", "hostname")
        if os.path.exists(hostname_file):
            try:
                with open(hostname_file, 'r') as f:
                    info.hostname = f.read().strip()
            except:
                pass

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _parse_os_release(self, filepath: str) -> Dict[str, str]:
        """Parse /etc/os-release file."""
        result = {}
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        result[key] = value.strip('"')
        except:
            pass
        return result

    def _parse_linux_users(self, passwd_file: str) -> List[str]:
        """Parse Linux users from /etc/passwd."""
        users = []
        try:
            with open(passwd_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username = parts[0]
                        uid = int(parts[2])
                        # Regular users typically have UID >= 1000
                        if uid >= 1000 and uid < 65534:
                            users.append(username)
        except:
            pass
        return users

    def _detect_android(self) -> Optional[OSInfo]:
        """Detect Android operating system."""
        info = OSInfo(os_type=OSType.ANDROID)
        confidence = 0.0
        artifacts = []

        # Check for Android-specific directories
        android_dirs = ["system", "data", "vendor", "boot"]
        for dir_name in android_dirs:
            if os.path.exists(os.path.join(self.mount_point, dir_name)):
                confidence += 0.15
                artifacts.append(f"/{dir_name}")

        # Check for build.prop
        build_prop = os.path.join(self.mount_point, "system", "build.prop")
        if os.path.exists(build_prop):
            confidence += 0.3
            artifacts.append("/system/build.prop")
            prop_data = self._parse_build_prop(build_prop)
            if prop_data:
                version = prop_data.get("ro.build.version.release")
                if version:
                    info.version = f"Android {version}"

        # Check for Dalvik cache
        if os.path.exists(os.path.join(self.mount_point, "data", "dalvik-cache")):
            confidence += 0.1
            artifacts.append("/data/dalvik-cache")

        # Check for app directories
        if os.path.exists(os.path.join(self.mount_point, "data", "app")):
            confidence += 0.1
            artifacts.append("/data/app")

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _parse_build_prop(self, filepath: str) -> Dict[str, str]:
        """Parse Android build.prop file."""
        result = {}
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        result[key.strip()] = value.strip()
        except:
            pass
        return result

    def _detect_macos(self) -> Optional[OSInfo]:
        """Detect macOS operating system."""
        info = OSInfo(os_type=OSType.MACOS)
        confidence = 0.0
        artifacts = []

        # Check for macOS-specific directories
        macos_dirs = [
            ("System", "Library"),
            ("Library",),
            ("Applications",),
            ("Users",),
            ("private", "var"),
        ]

        for path_parts in macos_dirs:
            if os.path.exists(os.path.join(self.mount_point, *path_parts)):
                confidence += 0.15
                artifacts.append("/" + "/".join(path_parts))

        # Check for macOS system files
        if os.path.exists(os.path.join(self.mount_point, "System", "Library", "CoreServices", "SystemVersion.plist")):
            confidence += 0.3
            artifacts.append("SystemVersion.plist")
            # TODO: Parse plist for version info

        # Check for .DS_Store files (strong indicator)
        for root, dirs, files in os.walk(self.mount_point):
            if ".DS_Store" in files:
                confidence += 0.1
                artifacts.append(".DS_Store files")
                break

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _detect_ios_backup(self) -> Optional[OSInfo]:
        """Detect iOS backup structure."""
        info = OSInfo(os_type=OSType.IOS)
        confidence = 0.0
        artifacts = []

        # Check for iOS backup files
        ios_files = ["Manifest.plist", "Manifest.db", "Info.plist", "Status.plist"]
        for filename in ios_files:
            if os.path.exists(os.path.join(self.mount_point, filename)):
                confidence += 0.2
                artifacts.append(filename)

        # Check for backup directory structure (40-char hex names)
        hex_pattern = re.compile(r'^[a-f0-9]{40}$')
        dirs_found = 0
        try:
            for item in os.listdir(self.mount_point):
                if hex_pattern.match(item):
                    dirs_found += 1
                    if dirs_found >= 5:
                        confidence += 0.2
                        artifacts.append("iOS backup directory structure")
                        break
        except:
            pass

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _detect_freebsd(self) -> Optional[OSInfo]:
        """Detect FreeBSD operating system."""
        info = OSInfo(os_type=OSType.FREEBSD)
        confidence = 0.0
        artifacts = []

        # Check for FreeBSD-specific paths
        if os.path.exists(os.path.join(self.mount_point, "boot", "kernel", "kernel")):
            confidence += 0.3
            artifacts.append("/boot/kernel/kernel")

        if os.path.exists(os.path.join(self.mount_point, "etc", "freebsd-update.conf")):
            confidence += 0.3
            artifacts.append("/etc/freebsd-update.conf")

        if os.path.exists(os.path.join(self.mount_point, "usr", "sbin", "freebsd-version")):
            confidence += 0.2
            artifacts.append("/usr/sbin/freebsd-version")

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def _detect_vmware_esx(self) -> Optional[OSInfo]:
        """Detect VMware ESX/ESXi."""
        info = OSInfo(os_type=OSType.VMWARE_ESX)
        confidence = 0.0
        artifacts = []

        # Check for VMware-specific paths
        vmware_indicators = [
            "/vmfs",
            "/bootbank",
            "/altbootbank",
            "/scratch",
        ]

        for path in vmware_indicators:
            if os.path.exists(os.path.join(self.mount_point, path.lstrip('/'))):
                confidence += 0.2
                artifacts.append(path)

        info.confidence = min(confidence, 1.0)
        info.artifacts_found = artifacts

        return info if confidence > 0 else None

    def get_artifact_locations(self) -> Dict[str, str]:
        """Get common artifact locations based on detected OS.

        Returns:
            Dictionary mapping artifact types to their paths
        """
        if not self.os_info:
            return {}

        locations = {}

        if self.os_info.os_type == OSType.WINDOWS:
            locations.update({
                "registry": "Windows/System32/config",
                "event_logs": "Windows/System32/winevt/Logs",
                "prefetch": "Windows/Prefetch",
                "users": "Users",
                "recycle_bin": "$Recycle.Bin",
                "browsers": "Users/*/AppData/Local",
                "temp": "Windows/Temp",
            })
        elif self.os_info.os_type == OSType.LINUX:
            locations.update({
                "logs": "var/log",
                "users": "home",
                "config": "etc",
                "temp": "tmp",
                "browsers": "home/*/.mozilla",
            })
        elif self.os_info.os_type == OSType.ANDROID:
            locations.update({
                "apps": "data/app",
                "app_data": "data/data",
                "logs": "data/log",
                "media": "sdcard/DCIM",
                "downloads": "sdcard/Download",
            })

        # Convert to absolute paths
        abs_locations = {}
        for key, path in locations.items():
            abs_locations[key] = os.path.join(self.mount_point, path)

        return abs_locations