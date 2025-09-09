"""Tool Manager for Digital Forensics Workbench.

This module handles all external tool integration, providing a unified interface
for calling command-line forensic tools and capturing their output.
"""

import os
import subprocess
import shutil
import tempfile
import json
import threading
import queue
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass
from enum import Enum
import platform


class ToolStatus(Enum):
    """Tool availability status."""
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    ERROR = "error"
    RUNNING = "running"


@dataclass
class ToolResult:
    """Container for tool execution results."""
    tool_name: str
    command: List[str]
    stdout: str
    stderr: str
    return_code: int
    success: bool
    output_files: List[str] = None

    def __post_init__(self):
        if self.output_files is None:
            self.output_files = []


class ExternalToolManager:
    """Manages external forensic tool execution."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize tool manager with optional configuration."""
        self.os_type = platform.system()
        self.tools_config = self._load_config(config_path)
        self.available_tools = {}
        self.temp_dir = tempfile.mkdtemp(prefix="dfw_tools_")
        self._check_all_tools()

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load tool configuration from file."""
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)

        # Default configuration
        return {
            "sleuthkit": {
                "commands": {
                    "mmls": "mmls",
                    "fls": "fls",
                    "icat": "icat",
                    "tsk_recover": "tsk_recover",
                    "tsk_gettimes": "tsk_gettimes"
                }
            },
            "volatility": {
                "command": "volatility3" if self.os_type != "Windows" else "volatility3.exe",
                "plugins": {
                    "windows": ["pslist", "pstree", "netscan", "filescan", "dlllist", "handles", "cmdline"],
                    "linux": ["linux.pslist", "linux.netstat", "linux.bash", "linux.check_modules"],
                    "mac": ["mac.pslist", "mac.netstat", "mac.bash_history"]
                }
            },
            "network": {
                "tshark": "tshark",
                "tcpdump": "tcpdump",
                "wireshark": "wireshark"
            },
            "carving": {
                "foremost": "foremost",
                "scalpel": "scalpel",
                "photorec": "photorec",
                "binwalk": "binwalk"
            },
            "registry": {
                "regripper": "rip.pl" if self.os_type != "Windows" else "rip.exe",
                "hivex": "hivexsh",
                "reged": "reged"
            },
            "timeline": {
                "plaso": "log2timeline.py",
                "psort": "psort.py",
                "mactime": "mactime"
            },
            "mobile": {
                "aleapp": "aleapp",
                "ileapp": "ileapp",
                "adb": "adb"
            },
            "analysis": {
                "yara": "yara",
                "bulk_extractor": "bulk_extractor",
                "strings": "strings",
                "exiftool": "exiftool",
                "pdfparser": "pdf-parser.py",
                "oletools": "olevba"
            },
            "disk": {
                "ewfmount": "ewfmount",
                "affuse": "affuse",
                "qemu-img": "qemu-img",
                "vboxmanage": "vboxmanage"
            }
        }

    def _check_all_tools(self) -> None:
        """Check availability of all configured tools."""
        for category, tools in self.tools_config.items():
            if isinstance(tools, dict):
                if "command" in tools:
                    # Single command tool
                    tool_path = shutil.which(tools["command"])
                    self.available_tools[tools["command"]] = {
                        "status": ToolStatus.AVAILABLE if tool_path else ToolStatus.NOT_FOUND,
                        "path": tool_path,
                        "category": category
                    }
                elif "commands" in tools:
                    # Multiple commands
                    for name, cmd in tools["commands"].items():
                        tool_path = shutil.which(cmd)
                        self.available_tools[cmd] = {
                            "status": ToolStatus.AVAILABLE if tool_path else ToolStatus.NOT_FOUND,
                            "path": tool_path,
                            "category": category
                        }
                else:
                    # Simple command mapping
                    for name, cmd in tools.items():
                        if isinstance(cmd, str):
                            tool_path = shutil.which(cmd)
                            self.available_tools[cmd] = {
                                "status": ToolStatus.AVAILABLE if tool_path else ToolStatus.NOT_FOUND,
                                "path": tool_path,
                                "category": category
                            }

    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available."""
        return tool_name in self.available_tools and \
            self.available_tools[tool_name]["status"] == ToolStatus.AVAILABLE

    def get_available_tools(self) -> Dict[str, Dict]:
        """Get list of available tools organized by category."""
        result = {}
        for tool, info in self.available_tools.items():
            category = info["category"]
            if category not in result:
                result[category] = {}
            result[category][tool] = info["status"] == ToolStatus.AVAILABLE
        return result

    def run_tool(self, tool_name: str, args: List[str],
                 callback: Optional[Callable] = None,
                 cwd: Optional[str] = None,
                 timeout: Optional[int] = None) -> ToolResult:
        """Run an external tool with arguments.

        Args:
            tool_name: Name of the tool to run
            args: Command line arguments
            callback: Optional callback for progress updates
            cwd: Working directory
            timeout: Timeout in seconds

        Returns:
            ToolResult with execution results
        """
        if not self.is_tool_available(tool_name):
            return ToolResult(
                tool_name=tool_name,
                command=[tool_name] + args,
                stdout="",
                stderr=f"Tool '{tool_name}' is not available",
                return_code=-1,
                success=False
            )

        tool_path = self.available_tools[tool_name]["path"]
        command = [tool_path] + args

        try:
            # Run the tool
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd
            )

            # Handle output with optional callback
            stdout_lines = []
            stderr_lines = []

            if callback:
                # Real-time output processing
                while True:
                    output = process.stdout.readline()
                    if output:
                        stdout_lines.append(output)
                        callback(output.strip())
                    elif process.poll() is not None:
                        break

                stderr = process.stderr.read()
                stderr_lines.append(stderr)
            else:
                # Wait for completion
                stdout, stderr = process.communicate(timeout=timeout)
                stdout_lines.append(stdout)
                stderr_lines.append(stderr)

            return ToolResult(
                tool_name=tool_name,
                command=command,
                stdout="".join(stdout_lines),
                stderr="".join(stderr_lines),
                return_code=process.returncode,
                success=process.returncode == 0
            )

        except subprocess.TimeoutExpired:
            process.kill()
            return ToolResult(
                tool_name=tool_name,
                command=command,
                stdout="",
                stderr="Process timed out",
                return_code=-1,
                success=False
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                command=command,
                stdout="",
                stderr=str(e),
                return_code=-1,
                success=False
            )

    # Sleuth Kit Tools
    def run_mmls(self, image_path: str) -> ToolResult:
        """Run mmls to list partitions."""
        return self.run_tool("mmls", [image_path])

    def run_fls(self, image_path: str, offset: Optional[int] = None,
                inode: Optional[str] = None) -> ToolResult:
        """Run fls to list files."""
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        if inode:
            args.append(inode)
        args.append(image_path)
        return self.run_tool("fls", args)

    def run_tsk_recover(self, image_path: str, output_dir: str,
                        offset: Optional[int] = None) -> ToolResult:
        """Run tsk_recover to recover deleted files."""
        args = []
        if offset:
            args.extend(["-o", str(offset)])
        args.extend(["-e", image_path, output_dir])
        return self.run_tool("tsk_recover", args)

    # Volatility Tools
    def run_volatility(self, memory_image: str, plugin: str,
                       output_format: str = "text",
                       extra_args: Optional[List[str]] = None) -> ToolResult:
        """Run Volatility plugin on memory image."""
        args = ["-f", memory_image]

        # Add plugin
        args.append(plugin)

        # Add output format
        if output_format != "text":
            args.extend(["-r", output_format])

        # Add extra arguments
        if extra_args:
            args.extend(extra_args)

        tool = self.tools_config["volatility"]["command"]
        return self.run_tool(tool, args)

    # Network Tools
    def run_tshark(self, pcap_file: str, display_filter: Optional[str] = None,
                   read_filter: Optional[str] = None,
                   fields: Optional[List[str]] = None) -> ToolResult:
        """Run tshark for packet analysis."""
        args = ["-r", pcap_file]

        if display_filter:
            args.extend(["-Y", display_filter])

        if read_filter:
            args.extend(["-R", read_filter])

        if fields:
            args.extend(["-T", "fields"])
            for field in fields:
                args.extend(["-e", field])

        return self.run_tool("tshark", args)

    def extract_pcap_files(self, pcap_file: str, output_dir: str) -> ToolResult:
        """Extract files from PCAP using tshark."""
        args = [
            "-r", pcap_file,
            "--export-objects", f"http,{output_dir}",
            "--export-objects", f"smb,{output_dir}",
            "--export-objects", f"tftp,{output_dir}"
        ]
        return self.run_tool("tshark", args)

    # File Carving Tools
    def run_foremost(self, image_path: str, output_dir: str,
                     config_file: Optional[str] = None) -> ToolResult:
        """Run Foremost for file carving."""
        args = ["-i", image_path, "-o", output_dir]

        if config_file:
            args.extend(["-c", config_file])
        else:
            args.append("-t all")  # Recover all file types

        return self.run_tool("foremost", args)

    def run_scalpel(self, image_path: str, output_dir: str,
                    config_file: Optional[str] = None) -> ToolResult:
        """Run Scalpel for file carving."""
        if not config_file:
            # Create default config
            config_file = os.path.join(self.temp_dir, "scalpel.conf")
            with open(config_file, 'w') as f:
                f.write(self._get_default_scalpel_config())

        args = ["-c", config_file, "-o", output_dir, image_path]
        return self.run_tool("scalpel", args)

    def run_binwalk(self, file_path: str, extract: bool = True) -> ToolResult:
        """Run Binwalk for firmware analysis."""
        args = []

        if extract:
            args.append("-e")  # Extract files

        args.append("-M")  # Matryoshka (recursive) scan
        args.append(file_path)

        return self.run_tool("binwalk", args)

    # Registry Tools
    def run_regripper(self, hive_path: str, plugin: Optional[str] = None,
                      profile: Optional[str] = None) -> ToolResult:
        """Run RegRipper on registry hive."""
        tool = self.tools_config["registry"]["regripper"]
        args = ["-r", hive_path]

        if plugin:
            args.extend(["-p", plugin])
        elif profile:
            args.extend(["-f", profile])
        else:
            args.extend(["-a"])  # Run all plugins

        return self.run_tool(tool, args)

    # Timeline Tools
    def run_plaso(self, evidence_path: str, output_file: str,
                  parsers: Optional[List[str]] = None) -> ToolResult:
        """Run Plaso log2timeline for timeline generation."""
        args = [output_file, evidence_path]

        if parsers:
            args.extend(["--parsers", ",".join(parsers)])

        return self.run_tool("log2timeline.py", args)

    def run_psort(self, plaso_file: str, output_format: str = "dynamic",
                  output_file: Optional[str] = None) -> ToolResult:
        """Run psort to process Plaso storage file."""
        args = ["-o", output_format]

        if output_file:
            args.extend(["-w", output_file])

        args.append(plaso_file)

        return self.run_tool("psort.py", args)

    def run_mactime(self, body_file: str, output_file: Optional[str] = None) -> ToolResult:
        """Run mactime for timeline visualization."""
        args = ["-b", body_file]

        if output_file:
            args = ["-d"] + args  # CSV output
            # Redirect to file
            with open(output_file, 'w') as f:
                result = self.run_tool("mactime", args)
                f.write(result.stdout)
                return result

        return self.run_tool("mactime", args)

    # Mobile Tools
    def run_aleapp(self, input_path: str, output_path: str) -> ToolResult:
        """Run ALEAPP for Android analysis."""
        args = ["-i", input_path, "-o", output_path]
        return self.run_tool("aleapp", args)

    def run_ileapp(self, input_path: str, output_path: str) -> ToolResult:
        """Run iLEAPP for iOS analysis."""
        args = ["-i", input_path, "-o", output_path]
        return self.run_tool("ileapp", args)

    def run_adb(self, command: str, device: Optional[str] = None) -> ToolResult:
        """Run ADB command."""
        args = []
        if device:
            args.extend(["-s", device])
        args.extend(command.split())
        return self.run_tool("adb", args)

    # Analysis Tools
    def run_yara(self, rules_file: str, target_path: str,
                 recursive: bool = True) -> ToolResult:
        """Run YARA for malware scanning."""
        args = []
        if recursive:
            args.append("-r")
        args.extend([rules_file, target_path])
        return self.run_tool("yara", args)

    def run_bulk_extractor(self, image_path: str, output_dir: str,
                           scanners: Optional[List[str]] = None) -> ToolResult:
        """Run Bulk Extractor for feature extraction."""
        args = ["-o", output_dir]

        if scanners:
            for scanner in scanners:
                args.extend(["-e", scanner])

        args.append(image_path)
        return self.run_tool("bulk_extractor", args)

    def run_strings(self, file_path: str, min_length: int = 4,
                    encoding: str = "s") -> ToolResult:
        """Run strings to extract text."""
        args = [f"-{encoding}", "-n", str(min_length), file_path]
        return self.run_tool("strings", args)

    def run_exiftool(self, file_path: str, recursive: bool = False) -> ToolResult:
        """Run ExifTool for metadata extraction."""
        args = []
        if recursive:
            args.append("-r")
        args.extend(["-j", file_path])  # JSON output
        return self.run_tool("exiftool", args)

    # Disk Image Tools
    def convert_e01_to_raw(self, e01_path: str, output_path: str) -> ToolResult:
        """Convert E01 to raw image using ewfexport."""
        args = ["-t", output_path, "-f", "raw", "-o", "0", e01_path]
        return self.run_tool("ewfexport", args)

    def mount_ewf(self, e01_path: str, mount_point: str) -> ToolResult:
        """Mount E01 image using ewfmount."""
        os.makedirs(mount_point, exist_ok=True)
        args = [e01_path, mount_point]
        return self.run_tool("ewfmount", args)

    def convert_vmdk_to_raw(self, vmdk_path: str, output_path: str) -> ToolResult:
        """Convert VMDK to raw using qemu-img."""
        args = ["convert", "-f", "vmdk", "-O", "raw", vmdk_path, output_path]
        return self.run_tool("qemu-img", args)

    # Batch Processing
    def run_batch(self, tasks: List[Tuple[str, List[str]]],
                  parallel: bool = False,
                  callback: Optional[Callable] = None) -> List[ToolResult]:
        """Run multiple tools in batch.

        Args:
            tasks: List of (tool_name, args) tuples
            parallel: Run tasks in parallel
            callback: Progress callback

        Returns:
            List of ToolResult objects
        """
        results = []

        if parallel:
            # Run in parallel using threads
            threads = []
            result_queue = queue.Queue()

            def run_task(tool_name, args, queue):
                result = self.run_tool(tool_name, args)
                queue.put(result)

            for tool_name, args in tasks:
                thread = threading.Thread(
                    target=run_task,
                    args=(tool_name, args, result_queue)
                )
                thread.start()
                threads.append(thread)

            # Wait for all threads
            for thread in threads:
                thread.join()

            # Collect results
            while not result_queue.empty():
                results.append(result_queue.get())
        else:
            # Run sequentially
            for i, (tool_name, args) in enumerate(tasks):
                if callback:
                    callback(f"Running {tool_name} ({i + 1}/{len(tasks)})")
                result = self.run_tool(tool_name, args)
                results.append(result)

        return results

    def _get_default_scalpel_config(self) -> str:
        """Get default Scalpel configuration."""
        return """
# Scalpel configuration file

# GIF and JPG
gif     y       5000000         \\x47\\x49\\x46\\x38\\x37\\x61    \\x00\\x3b
gif     y       5000000         \\x47\\x49\\x46\\x38\\x39\\x61    \\x00\\x3b
jpg     y       20000000        \\xff\\xd8\\xff                   \\xff\\xd9

# PNG
png     y       20000000        \\x89\\x50\\x4e\\x47              \\x49\\x45\\x4e\\x44

# PDF
pdf     y       50000000        \\x25\\x50\\x44\\x46              \\x25\\x25\\x45\\x4f\\x46

# Microsoft Office
doc     y       10000000        \\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1
docx    y       10000000        \\x50\\x4b\\x03\\x04\\x14\\x00\\x06\\x00

# ZIP
zip     y       10000000        \\x50\\x4b\\x03\\x04              \\x50\\x4b\\x05\\x06
"""

    def cleanup(self) -> None:
        """Clean up temporary files."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)