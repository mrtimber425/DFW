"""Windows Registry forensics module for analyzing registry hives.

This module provides comprehensive Windows registry analysis capabilities,
including user activity tracking, installed software enumeration, USB device
history, network connections, and various Windows artifacts extraction.
"""

import os
import struct
import json
import subprocess
import shutil
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class RegistryArtifact:
    """Container for registry artifacts."""
    artifact_type: str
    key_path: str
    value_name: Optional[str] = None
    value_data: Any = None
    timestamp: Optional[datetime] = None
    description: Optional[str] = None
    hive: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class RegistryAnalyzer:
    """Windows Registry forensics analyzer."""

    def __init__(self, mount_point: str):
        """Initialize registry analyzer with mount point.

        Args:
            mount_point: Path to mounted Windows filesystem
        """
        self.mount_point = mount_point
        self.artifacts = []
        self.temp_dir = tempfile.mkdtemp(prefix="registry_forensics_")
        self.hive_paths = self._locate_registry_hives()

    def __del__(self):
        """Cleanup temporary directory."""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _locate_registry_hives(self) -> Dict[str, str]:
        """Locate registry hive files on the mounted filesystem."""
        hives = {}

        # System hives location
        system_config = os.path.join(self.mount_point, "Windows", "System32", "config")

        # System hives
        system_hives = {
            "SAM": "SAM",
            "SYSTEM": "SYSTEM",
            "SOFTWARE": "SOFTWARE",
            "SECURITY": "SECURITY",
            "DEFAULT": "DEFAULT",
        }

        for hive_name, filename in system_hives.items():
            hive_path = os.path.join(system_config, filename)
            if os.path.exists(hive_path):
                hives[hive_name] = hive_path

        # User hives (NTUSER.DAT)
        users_dir = os.path.join(self.mount_point, "Users")
        if os.path.exists(users_dir):
            for user in os.listdir(users_dir):
                if user in ["Default", "Public", "All Users"]:
                    continue
                ntuser_path = os.path.join(users_dir, user, "NTUSER.DAT")
                if os.path.exists(ntuser_path):
                    hives[f"NTUSER_{user}"] = ntuser_path

                # UsrClass.dat (ShellBags, etc.)
                usrclass_path = os.path.join(users_dir, user, "AppData", "Local",
                                             "Microsoft", "Windows", "UsrClass.dat")
                if os.path.exists(usrclass_path):
                    hives[f"USRCLASS_{user}"] = usrclass_path

        return hives

    def analyze_all(self) -> List[RegistryArtifact]:
        """Perform comprehensive registry analysis.

        Returns:
            List of all registry artifacts found
        """
        self.artifacts = []

        analyzers = [
            self._analyze_system_info,
            self._analyze_installed_software,
            self._analyze_usb_devices,
            self._analyze_network_config,
            self._analyze_user_activity,
            self._analyze_run_keys,
            self._analyze_services,
            self._analyze_user_assist,
            self._analyze_typed_urls,
            self._analyze_mru_lists,
            self._analyze_shellbags,
            self._analyze_uninstall_info,
            self._analyze_timezone_info,
            self._analyze_computer_info,
            self._analyze_file_associations,
        ]

        for analyzer in analyzers:
            try:
                analyzer()
            except Exception as e:
                print(f"Error in {analyzer.__name__}: {e}")

        return self.artifacts

    def _parse_registry_value(self, hive_path: str, key_path: str,
                              value_name: Optional[str] = None) -> Optional[Any]:
        """Parse a registry value using reg.exe or Python registry library.

        This is a simplified implementation. In production, you'd use
        python-registry or regipy library for proper parsing.
        """
        # This would require python-registry or regipy library
        # For now, returning None as placeholder
        return None

    def _analyze_system_info(self) -> None:
        """Extract system information from registry."""
        if "SYSTEM" not in self.hive_paths:
            return

        # Computer name
        artifact = RegistryArtifact(
            artifact_type="system_info",
            key_path="ControlSet001\\Control\\ComputerName\\ComputerName",
            value_name="ComputerName",
            description="Computer name",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        # Windows version
        artifact = RegistryArtifact(
            artifact_type="system_info",
            key_path="ControlSet001\\Control\\Windows",
            value_name="CSDVersion",
            description="Windows service pack version",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        # Install date
        artifact = RegistryArtifact(
            artifact_type="system_info",
            key_path="Setup",
            value_name="InstallDate",
            description="Windows installation date",
            hive="SOFTWARE"
        )
        self.artifacts.append(artifact)

        # Product name
        artifact = RegistryArtifact(
            artifact_type="system_info",
            key_path="Microsoft\\Windows NT\\CurrentVersion",
            value_name="ProductName",
            description="Windows product name",
            hive="SOFTWARE"
        )
        self.artifacts.append(artifact)

        # Build number
        artifact = RegistryArtifact(
            artifact_type="system_info",
            key_path="Microsoft\\Windows NT\\CurrentVersion",
            value_name="CurrentBuild",
            description="Windows build number",
            hive="SOFTWARE"
        )
        self.artifacts.append(artifact)

    def _analyze_installed_software(self) -> None:
        """Extract installed software information."""
        if "SOFTWARE" not in self.hive_paths:
            return

        # 64-bit software
        artifact = RegistryArtifact(
            artifact_type="installed_software",
            key_path="Microsoft\\Windows\\CurrentVersion\\Uninstall",
            description="64-bit installed software",
            hive="SOFTWARE",
            metadata={"architecture": "x64"}
        )
        self.artifacts.append(artifact)

        # 32-bit software on 64-bit systems
        artifact = RegistryArtifact(
            artifact_type="installed_software",
            key_path="Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            description="32-bit installed software",
            hive="SOFTWARE",
            metadata={"architecture": "x86"}
        )
        self.artifacts.append(artifact)

    def _analyze_usb_devices(self) -> None:
        """Extract USB device history."""
        if "SYSTEM" not in self.hive_paths:
            return

        # USB devices
        artifact = RegistryArtifact(
            artifact_type="usb_device",
            key_path="ControlSet001\\Enum\\USB",
            description="USB devices connected to system",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        # USB storage devices
        artifact = RegistryArtifact(
            artifact_type="usb_storage",
            key_path="ControlSet001\\Enum\\USBSTOR",
            description="USB storage devices",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        # Mounted devices
        artifact = RegistryArtifact(
            artifact_type="mounted_devices",
            key_path="MountedDevices",
            description="Previously mounted devices",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

    def _analyze_network_config(self) -> None:
        """Extract network configuration."""
        if "SYSTEM" not in self.hive_paths:
            return

        # Network interfaces
        artifact = RegistryArtifact(
            artifact_type="network_interface",
            key_path="ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces",
            description="Network interface configurations",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        # Network profiles
        if "SOFTWARE" in self.hive_paths:
            artifact = RegistryArtifact(
                artifact_type="network_profile",
                key_path="Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
                description="Network connection profiles",
                hive="SOFTWARE"
            )
            self.artifacts.append(artifact)

            # Known networks
            artifact = RegistryArtifact(
                artifact_type="known_networks",
                key_path="Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
                description="Previously connected networks",
                hive="SOFTWARE"
            )
            self.artifacts.append(artifact)

    def _analyze_user_activity(self) -> None:
        """Extract user activity artifacts."""
        # Process each user's NTUSER.DAT
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            # Recent documents
            artifact = RegistryArtifact(
                artifact_type="recent_docs",
                key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
                description=f"Recent documents for {username}",
                hive=hive_name
            )
            self.artifacts.append(artifact)

            # Run MRU
            artifact = RegistryArtifact(
                artifact_type="run_mru",
                key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
                description=f"Run dialog history for {username}",
                hive=hive_name
            )
            self.artifacts.append(artifact)

            # Typed paths
            artifact = RegistryArtifact(
                artifact_type="typed_paths",
                key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
                description=f"Typed paths in Explorer for {username}",
                hive=hive_name
            )
            self.artifacts.append(artifact)

    def _analyze_run_keys(self) -> None:
        """Extract autorun entries."""
        # System-wide autorun
        if "SOFTWARE" in self.hive_paths:
            run_keys = [
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Microsoft\\Windows\\CurrentVersion\\RunServices",
                "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]

            for key in run_keys:
                artifact = RegistryArtifact(
                    artifact_type="autorun",
                    key_path=key,
                    description="System-wide autorun entry",
                    hive="SOFTWARE"
                )
                self.artifacts.append(artifact)

        # User-specific autorun
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            user_run_keys = [
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ]

            for key in user_run_keys:
                artifact = RegistryArtifact(
                    artifact_type="autorun",
                    key_path=key,
                    description=f"User autorun entry for {username}",
                    hive=hive_name
                )
                self.artifacts.append(artifact)

    def _analyze_services(self) -> None:
        """Extract Windows services information."""
        if "SYSTEM" not in self.hive_paths:
            return

        artifact = RegistryArtifact(
            artifact_type="services",
            key_path="ControlSet001\\Services",
            description="Windows services configuration",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

    def _analyze_user_assist(self) -> None:
        """Extract UserAssist data (program execution)."""
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            artifact = RegistryArtifact(
                artifact_type="user_assist",
                key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                description=f"Program execution history for {username}",
                hive=hive_name,
                metadata={"note": "Values are ROT13 encoded"}
            )
            self.artifacts.append(artifact)

    def _analyze_typed_urls(self) -> None:
        """Extract typed URLs from Internet Explorer."""
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            artifact = RegistryArtifact(
                artifact_type="typed_urls",
                key_path="Software\\Microsoft\\Internet Explorer\\TypedURLs",
                description=f"IE typed URLs for {username}",
                hive=hive_name
            )
            self.artifacts.append(artifact)

    def _analyze_mru_lists(self) -> None:
        """Extract various MRU (Most Recently Used) lists."""
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            mru_keys = [
                ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
                 "Open/Save dialog MRU"),
                ("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
                 "Last visited folder MRU"),
                ("Software\\Microsoft\\Office\\16.0\\Common\\Open Find\\Microsoft Word\\Settings\\MRU",
                 "Microsoft Word MRU"),
                ("Software\\Microsoft\\Office\\16.0\\Common\\Open Find\\Microsoft Excel\\Settings\\MRU",
                 "Microsoft Excel MRU"),
            ]

            for key_path, description in mru_keys:
                artifact = RegistryArtifact(
                    artifact_type="mru_list",
                    key_path=key_path,
                    description=f"{description} for {username}",
                    hive=hive_name
                )
                self.artifacts.append(artifact)

    def _analyze_shellbags(self) -> None:
        """Extract ShellBag data (folder access history)."""
        for hive_name, hive_path in self.hive_paths.items():
            if hive_name.startswith("USRCLASS_"):
                username = hive_name.replace("USRCLASS_", "")

                artifact = RegistryArtifact(
                    artifact_type="shellbags",
                    key_path="Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    description=f"Folder access history for {username}",
                    hive=hive_name
                )
                self.artifacts.append(artifact)
            elif hive_name.startswith("NTUSER_"):
                username = hive_name.replace("NTUSER_", "")

                artifact = RegistryArtifact(
                    artifact_type="shellbags",
                    key_path="Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    description=f"Folder view preferences for {username}",
                    hive=hive_name
                )
                self.artifacts.append(artifact)

    def _analyze_uninstall_info(self) -> None:
        """Extract software uninstall information."""
        if "SOFTWARE" not in self.hive_paths:
            return

        artifact = RegistryArtifact(
            artifact_type="uninstall_info",
            key_path="Microsoft\\Windows\\CurrentVersion\\Uninstall",
            description="Software uninstall information",
            hive="SOFTWARE"
        )
        self.artifacts.append(artifact)

    def _analyze_timezone_info(self) -> None:
        """Extract timezone information."""
        if "SYSTEM" not in self.hive_paths:
            return

        artifact = RegistryArtifact(
            artifact_type="timezone",
            key_path="ControlSet001\\Control\\TimeZoneInformation",
            description="System timezone configuration",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

    def _analyze_computer_info(self) -> None:
        """Extract computer and domain information."""
        if "SYSTEM" not in self.hive_paths:
            return

        # Computer name and domain
        artifact = RegistryArtifact(
            artifact_type="computer_info",
            key_path="ControlSet001\\Services\\Tcpip\\Parameters",
            value_name="Hostname",
            description="Computer hostname",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

        artifact = RegistryArtifact(
            artifact_type="computer_info",
            key_path="ControlSet001\\Services\\Tcpip\\Parameters",
            value_name="Domain",
            description="Domain name",
            hive="SYSTEM"
        )
        self.artifacts.append(artifact)

    def _analyze_file_associations(self) -> None:
        """Extract file associations."""
        for hive_name, hive_path in self.hive_paths.items():
            if not hive_name.startswith("NTUSER_"):
                continue

            username = hive_name.replace("NTUSER_", "")

            artifact = RegistryArtifact(
                artifact_type="file_associations",
                key_path="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts",
                description=f"User file associations for {username}",
                hive=hive_name
            )
            self.artifacts.append(artifact)

    def run_regripper(self, plugin: Optional[str] = None) -> str:
        """Run RegRipper on registry hives.

        Args:
            plugin: Specific RegRipper plugin to run, or None for all

        Returns:
            RegRipper output as string
        """
        # Check if RegRipper is available
        if shutil.which("rip.pl") is None and shutil.which("rip.exe") is None:
            return "RegRipper is not installed or not in PATH"

        output = []

        for hive_name, hive_path in self.hive_paths.items():
            # Copy hive to temp location
            temp_hive = os.path.join(self.temp_dir, os.path.basename(hive_path))
            shutil.copy2(hive_path, temp_hive)

            # Determine RegRipper profile based on hive type
            if hive_name == "SAM":
                profile = "sam"
            elif hive_name == "SYSTEM":
                profile = "system"
            elif hive_name == "SOFTWARE":
                profile = "software"
            elif hive_name == "SECURITY":
                profile = "security"
            elif hive_name.startswith("NTUSER"):
                profile = "ntuser"
            elif hive_name.startswith("USRCLASS"):
                profile = "usrclass"
            else:
                profile = "all"

            # Run RegRipper
            cmd = ["rip.pl" if os.name != 'nt' else "rip.exe"]

            if plugin:
                cmd.extend(["-r", temp_hive, "-p", plugin])
            else:
                cmd.extend(["-r", temp_hive, "-f", profile])

            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                output.append(f"\n=== {hive_name} ===\n")
                output.append(result.stdout)
                if result.stderr:
                    output.append(f"Errors: {result.stderr}")
            except Exception as e:
                output.append(f"Error processing {hive_name}: {e}")

        return "\n".join(output)

    def export_timeline(self) -> List[Tuple[datetime, str, str]]:
        """Export registry timeline events.

        Returns:
            List of (timestamp, source, description) tuples
        """
        timeline = []

        # Add key last write times
        for artifact in self.artifacts:
            if artifact.timestamp:
                timeline.append((
                    artifact.timestamp,
                    f"{artifact.hive}/{artifact.key_path}",
                    artifact.description or artifact.artifact_type
                ))

        # Sort by timestamp
        timeline.sort(key=lambda x: x[0])

        return timeline

    def export_report(self, format: str = "json") -> str:
        """Export registry analysis report.

        Args:
            format: Output format (json, html, text)

        Returns:
            Formatted report as string
        """
        if format == "json":
            return self._export_json()
        elif format == "html":
            return self._export_html()
        elif format == "text":
            return self._export_text()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _export_json(self) -> str:
        """Export artifacts as JSON."""
        export_data = []

        for artifact in self.artifacts:
            export_data.append({
                "type": artifact.artifact_type,
                "hive": artifact.hive,
                "key": artifact.key_path,
                "value": artifact.value_name,
                "data": artifact.value_data,
                "timestamp": artifact.timestamp.isoformat() if artifact.timestamp else None,
                "description": artifact.description,
                "metadata": artifact.metadata,
            })

        return json.dumps(export_data, indent=2, default=str)

    def _export_html(self) -> str:
        """Export artifacts as HTML report."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Registry Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h2 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 5px; }
        .artifact { margin: 10px 0; padding: 10px; background: #f5f5f5; border-left: 3px solid #4CAF50; }
        .artifact-type { font-weight: bold; color: #4CAF50; }
        .key-path { font-family: monospace; background: #e0e0e0; padding: 2px 4px; }
        .description { font-style: italic; color: #666; }
    </style>
</head>
<body>
    <h1>Windows Registry Analysis Report</h1>
    <p>Generated: {}</p>
    <p>Total artifacts: {}</p>
""".format(datetime.now().isoformat(), len(self.artifacts))

        # Group artifacts by type
        by_type = {}
        for artifact in self.artifacts:
            if artifact.artifact_type not in by_type:
                by_type[artifact.artifact_type] = []
            by_type[artifact.artifact_type].append(artifact)

        # Generate sections
        for artifact_type, artifacts in by_type.items():
            html += f"<h2>{artifact_type.replace('_', ' ').title()}</h2>\n"

            for artifact in artifacts:
                html += '<div class="artifact">\n'
                html += f'<span class="artifact-type">{artifact.artifact_type}</span><br>\n'
                html += f'<span class="key-path">{artifact.hive}\\{artifact.key_path}</span><br>\n'

                if artifact.value_name:
                    html += f'Value: {artifact.value_name}<br>\n'
                if artifact.description:
                    html += f'<span class="description">{artifact.description}</span><br>\n'

                html += '</div>\n'

        html += """
</body>
</html>
"""
        return html

    def _export_text(self) -> str:
        """Export artifacts as text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("WINDOWS REGISTRY ANALYSIS REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Mount Point: {self.mount_point}")
        lines.append(f"Total Artifacts: {len(self.artifacts)}")
        lines.append("")

        # List available hives
        lines.append("Available Registry Hives:")
        for hive_name, hive_path in self.hive_paths.items():
            lines.append(f"  - {hive_name}: {hive_path}")
        lines.append("")

        # Group artifacts by type
        by_type = {}
        for artifact in self.artifacts:
            if artifact.artifact_type not in by_type:
                by_type[artifact.artifact_type] = []
            by_type[artifact.artifact_type].append(artifact)

        # Generate sections
        for artifact_type, artifacts in by_type.items():
            lines.append("-" * 80)
            lines.append(artifact_type.replace('_', ' ').upper())
            lines.append("-" * 80)

            for artifact in artifacts:
                lines.append(f"Hive: {artifact.hive}")
                lines.append(f"Key: {artifact.key_path}")

                if artifact.value_name:
                    lines.append(f"Value: {artifact.value_name}")
                if artifact.value_data:
                    lines.append(f"Data: {artifact.value_data}")
                if artifact.description:
                    lines.append(f"Description: {artifact.description}")
                if artifact.timestamp:
                    lines.append(f"Timestamp: {artifact.timestamp.isoformat()}")

                lines.append("")

        return "\n".join(lines)