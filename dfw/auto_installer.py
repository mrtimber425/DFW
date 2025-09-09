"""Automatic Tool Installer for Digital Forensics Workbench.

This module handles automatic detection and installation of required forensic tools
based on the operating system.
"""

import os
import sys
import platform
import subprocess
import shutil
import urllib.request
import tempfile
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json
import threading
from tkinter import messagebox, Toplevel, Label, Text, Button, Frame
from tkinter import ttk, BOTH, END, X, Y, LEFT, RIGHT, BOTTOM


class ToolInstaller:
    """Handles automatic installation of forensic tools."""
    
    def __init__(self, parent_window=None):
        self.parent = parent_window
        self.os_type = platform.system()
        self.arch = platform.machine()
        self.distro = self._get_linux_distro() if self.os_type == "Linux" else None
        
        # Tool definitions
        self.tools = {
            "plaso": {
                "name": "Plaso (log2timeline/psort)",
                "description": "Timeline generation and analysis",
                "linux_install": "pip3 install plaso",
                "windows_available": False,
                "check_command": ["log2timeline.py", "--version"],
                "required": True
            },
            "sleuthkit": {
                "name": "The Sleuth Kit",
                "description": "Disk and file system analysis",
                "linux_install": "apt-get install sleuthkit",
                "windows_available": True,
                "windows_url": "https://github.com/sleuthkit/sleuthkit/releases",
                "check_command": ["fls", "-V"],
                "required": True
            },
            "volatility": {
                "name": "Volatility 3",
                "description": "Memory analysis framework",
                "linux_install": "pip3 install volatility3",
                "windows_available": True,
                "windows_install": "pip install volatility3",
                "check_command": ["vol", "--help"],
                "required": True
            },
            "yara": {
                "name": "YARA",
                "description": "Malware identification and classification",
                "linux_install": "apt-get install yara && pip3 install yara-python",
                "windows_available": True,
                "windows_install": "pip install yara-python",
                "check_command": ["yara", "--version"],
                "required": False
            },
            "bulk_extractor": {
                "name": "Bulk Extractor",
                "description": "Digital forensics tool for extracting information",
                "linux_install": "apt-get install bulk-extractor",
                "windows_available": False,
                "check_command": ["bulk_extractor", "-h"],
                "required": False
            },
            "regripper": {
                "name": "RegRipper",
                "description": "Windows registry analysis",
                "linux_install": "git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper",
                "windows_available": True,
                "windows_url": "https://github.com/keydet89/RegRipper3.0",
                "check_command": ["perl", "/opt/regripper/rip.pl"],
                "required": False
            },
            "autopsy": {
                "name": "Autopsy",
                "description": "Digital forensics platform",
                "linux_install": "snap install autopsy",
                "windows_available": True,
                "windows_url": "https://www.autopsy.com/download/",
                "check_command": ["autopsy", "--version"],
                "required": False
            },
            "binwalk": {
                "name": "Binwalk",
                "description": "Firmware analysis tool",
                "linux_install": "apt-get install binwalk",
                "windows_available": True,
                "windows_install": "pip install binwalk",
                "check_command": ["binwalk", "--help"],
                "required": False
            },
            "foremost": {
                "name": "Foremost",
                "description": "File carving tool",
                "linux_install": "apt-get install foremost",
                "windows_available": False,
                "check_command": ["foremost", "-V"],
                "required": False
            },
            "scalpel": {
                "name": "Scalpel",
                "description": "File carving tool",
                "linux_install": "apt-get install scalpel",
                "windows_available": False,
                "check_command": ["scalpel", "-V"],
                "required": False
            }
        }
    
    def _get_linux_distro(self) -> Optional[str]:
        """Get Linux distribution name."""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"')
        except:
            pass
        return None
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a tool is available on the system."""
        tool_info = self.tools.get(tool_name)
        if not tool_info:
            return False
        
        check_cmd = tool_info["check_command"]
        try:
            result = subprocess.run(check_cmd, capture_output=True, timeout=10)
            return result.returncode == 0
        except:
            return False
    
    def get_tool_status(self) -> Dict[str, Dict]:
        """Get status of all tools."""
        status = {}
        for tool_name, tool_info in self.tools.items():
            available = self.check_tool_availability(tool_name)
            can_install = self._can_install_tool(tool_name)
            
            status[tool_name] = {
                "name": tool_info["name"],
                "description": tool_info["description"],
                "available": available,
                "can_install": can_install,
                "required": tool_info["required"],
                "os_supported": self._is_tool_supported(tool_name)
            }
        
        return status
    
    def _can_install_tool(self, tool_name: str) -> bool:
        """Check if tool can be automatically installed."""
        tool_info = self.tools[tool_name]
        
        if self.os_type == "Linux":
            return "linux_install" in tool_info
        elif self.os_type == "Windows":
            return tool_info.get("windows_available", False) and "windows_install" in tool_info
        
        return False
    
    def _is_tool_supported(self, tool_name: str) -> bool:
        """Check if tool is supported on current OS."""
        tool_info = self.tools[tool_name]
        
        if self.os_type == "Linux":
            return True  # Most tools work on Linux
        elif self.os_type == "Windows":
            return tool_info.get("windows_available", False)
        
        return False
    
    def install_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Install a specific tool."""
        tool_info = self.tools.get(tool_name)
        if not tool_info:
            return False, f"Unknown tool: {tool_name}"
        
        if not self._is_tool_supported(tool_name):
            return False, f"{tool_info['name']} is not supported on {self.os_type}"
        
        try:
            if self.os_type == "Linux":
                return self._install_linux_tool(tool_name, tool_info)
            elif self.os_type == "Windows":
                return self._install_windows_tool(tool_name, tool_info)
            else:
                return False, f"Unsupported operating system: {self.os_type}"
        
        except Exception as e:
            return False, f"Installation failed: {str(e)}"
    
    def _install_linux_tool(self, tool_name: str, tool_info: Dict) -> Tuple[bool, str]:
        """Install tool on Linux."""
        install_cmd = tool_info.get("linux_install")
        if not install_cmd:
            return False, "No Linux installation method available"
        
        # Handle different installation methods
        if install_cmd.startswith("apt-get"):
            # Update package list first
            subprocess.run(["sudo", "apt-get", "update"], check=False)
            cmd = ["sudo"] + install_cmd.split()
        elif install_cmd.startswith("pip"):
            cmd = install_cmd.split()
        elif install_cmd.startswith("snap"):
            cmd = ["sudo"] + install_cmd.split()
        elif install_cmd.startswith("git clone"):
            # Handle git clone specially
            parts = install_cmd.split()
            repo_url = parts[2]
            dest_path = parts[3] if len(parts) > 3 else f"/tmp/{tool_name}"
            cmd = ["git", "clone", repo_url, dest_path]
        else:
            cmd = install_cmd.split()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return True, f"{tool_info['name']} installed successfully"
            else:
                return False, f"Installation failed: {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, f"Installation error: {str(e)}"
    
    def _install_windows_tool(self, tool_name: str, tool_info: Dict) -> Tuple[bool, str]:
        """Install tool on Windows."""
        if "windows_install" in tool_info:
            install_cmd = tool_info["windows_install"]
            cmd = install_cmd.split()
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    return True, f"{tool_info['name']} installed successfully"
                else:
                    return False, f"Installation failed: {result.stderr}"
            except Exception as e:
                return False, f"Installation error: {str(e)}"
        else:
            # Provide download URL
            url = tool_info.get("windows_url", "")
            return False, f"Manual installation required. Download from: {url}"
    
    def install_all_tools(self, progress_callback=None) -> Dict[str, Tuple[bool, str]]:
        """Install all available tools."""
        results = {}
        total_tools = len([t for t in self.tools.keys() if self._can_install_tool(t)])
        installed = 0
        
        for tool_name in self.tools.keys():
            if self._can_install_tool(tool_name):
                if progress_callback:
                    progress_callback(f"Installing {self.tools[tool_name]['name']}...", 
                                    int((installed / total_tools) * 100))
                
                success, message = self.install_tool(tool_name)
                results[tool_name] = (success, message)
                installed += 1
                
                if progress_callback:
                    progress_callback(f"Completed {self.tools[tool_name]['name']}", 
                                    int((installed / total_tools) * 100))
        
        return results
    
    def show_installation_dialog(self):
        """Show GUI dialog for tool installation."""
        if not self.parent:
            return
        
        # Check OS compatibility first
        if self.os_type == "Windows":
            self._show_windows_warning()
            return
        
        dialog = Toplevel(self.parent)
        dialog.title("Forensic Tools Installation")
        dialog.geometry("700x600")
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Header
        header_frame = Frame(dialog)
        header_frame.pack(fill=X, padx=10, pady=10)
        
        Label(header_frame, text="Digital Forensics Tools Setup", 
              font=('Arial', 14, 'bold')).pack()
        Label(header_frame, text=f"Operating System: {self.os_type} ({self.distro})", 
              font=('Arial', 10)).pack()
        
        # Tool status
        status_frame = Frame(dialog)
        status_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        Label(status_frame, text="Tool Status:", font=('Arial', 12, 'bold')).pack(anchor='w')
        
        # Create treeview for tool status
        columns = ('Tool', 'Status', 'Description')
        tree = ttk.Treeview(status_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(status_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        # Populate tool status
        tool_status = self.get_tool_status()
        for tool_name, status in tool_status.items():
            status_text = "✓ Installed" if status["available"] else "✗ Missing"
            if not status["os_supported"]:
                status_text = "⚠ Not supported"
            
            tree.insert('', 'end', values=(
                status["name"],
                status_text,
                status["description"]
            ))
        
        # Progress bar
        progress_frame = Frame(dialog)
        progress_frame.pack(fill=X, padx=10, pady=5)
        
        progress_label = Label(progress_frame, text="Ready to install tools")
        progress_label.pack()
        
        progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        progress_bar.pack(fill=X, pady=5)
        
        # Log area
        log_frame = Frame(dialog)
        log_frame.pack(fill=X, padx=10, pady=5)
        
        Label(log_frame, text="Installation Log:", font=('Arial', 10, 'bold')).pack(anchor='w')
        log_text = Text(log_frame, height=8)
        log_text.pack(fill=X)
        
        # Buttons
        button_frame = Frame(dialog)
        button_frame.pack(fill=X, padx=10, pady=10)
        
        def update_progress(message, percent):
            progress_label.config(text=message)
            progress_bar['value'] = percent
            log_text.insert(END, f"{message}\n")
            log_text.see(END)
            dialog.update()
        
        def install_all():
            install_button.config(state='disabled')
            log_text.delete('1.0', END)
            log_text.insert(END, "Starting installation...\n")
            
            def install_thread():
                try:
                    results = self.install_all_tools(update_progress)
                    
                    # Update tree with new status
                    for item in tree.get_children():
                        tree.delete(item)
                    
                    updated_status = self.get_tool_status()
                    for tool_name, status in updated_status.items():
                        status_text = "✓ Installed" if status["available"] else "✗ Missing"
                        if not status["os_supported"]:
                            status_text = "⚠ Not supported"
                        
                        tree.insert('', 'end', values=(
                            status["name"],
                            status_text,
                            status["description"]
                        ))
                    
                    # Show summary
                    successful = sum(1 for success, _ in results.values() if success)
                    total = len(results)
                    
                    log_text.insert(END, f"\nInstallation complete: {successful}/{total} tools installed successfully\n")
                    progress_label.config(text=f"Installation complete: {successful}/{total} successful")
                    
                except Exception as e:
                    log_text.insert(END, f"Installation error: {str(e)}\n")
                finally:
                    install_button.config(state='normal')
            
            threading.Thread(target=install_thread, daemon=True).start()
        
        install_button = Button(button_frame, text="Install All Tools", command=install_all)
        install_button.pack(side=LEFT, padx=5)
        
        Button(button_frame, text="Refresh Status", 
               command=lambda: self._refresh_tool_status(tree)).pack(side=LEFT, padx=5)
        
        Button(button_frame, text="Close", command=dialog.destroy).pack(side=RIGHT, padx=5)
    
    def _refresh_tool_status(self, tree):
        """Refresh tool status in the tree."""
        for item in tree.get_children():
            tree.delete(item)
        
        tool_status = self.get_tool_status()
        for tool_name, status in tool_status.items():
            status_text = "✓ Installed" if status["available"] else "✗ Missing"
            if not status["os_supported"]:
                status_text = "⚠ Not supported"
            
            tree.insert('', 'end', values=(
                status["name"],
                status_text,
                status["description"]
            ))
    
    def _show_windows_warning(self):
        """Show warning dialog for Windows users."""
        warning_dialog = Toplevel(self.parent)
        warning_dialog.title("Windows Compatibility Notice")
        warning_dialog.geometry("600x400")
        warning_dialog.transient(self.parent)
        warning_dialog.grab_set()
        
        # Warning content
        content_frame = Frame(warning_dialog)
        content_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        Label(content_frame, text="⚠ Windows Compatibility Notice", 
              font=('Arial', 16, 'bold'), fg='orange').pack(pady=10)
        
        warning_text = """
The Digital Forensics Workbench is designed to work optimally on Linux systems.

Windows Limitations:
• Many forensic tools (Plaso, Bulk Extractor, Foremost, etc.) are not available on Windows
• Some tools require complex manual installation
• Performance may be reduced compared to Linux

Recommendations:
1. Use a Linux virtual machine (Ubuntu, Kali Linux)
2. Use Windows Subsystem for Linux (WSL2)
3. Run on a dedicated Linux forensic workstation

Available on Windows:
• Volatility 3 (memory analysis)
• YARA (malware scanning)
• Some basic tools

For the best forensic analysis experience, please run this application on Linux.
        """
        
        Label(content_frame, text=warning_text, justify=LEFT, 
              font=('Arial', 10), wraplength=550).pack(pady=10)
        
        # Buttons
        button_frame = Frame(warning_dialog)
        button_frame.pack(fill=X, padx=20, pady=10)
        
        def install_available():
            warning_dialog.destroy()
            # Install only Windows-compatible tools
            self._install_windows_tools()
        
        Button(button_frame, text="Install Available Tools", 
               command=install_available).pack(side=LEFT, padx=5)
        
        Button(button_frame, text="Continue Anyway", 
               command=warning_dialog.destroy).pack(side=LEFT, padx=5)
        
        Button(button_frame, text="Exit Application", 
               command=self.parent.quit).pack(side=RIGHT, padx=5)
    
    def _install_windows_tools(self):
        """Install tools available on Windows."""
        dialog = Toplevel(self.parent)
        dialog.title("Windows Tool Installation")
        dialog.geometry("500x400")
        
        Label(dialog, text="Installing Windows-Compatible Tools", 
              font=('Arial', 14, 'bold')).pack(pady=10)
        
        log_text = Text(dialog, height=20)
        log_text.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        def install_windows_thread():
            windows_tools = [name for name, info in self.tools.items() 
                           if info.get("windows_available", False)]
            
            for tool_name in windows_tools:
                log_text.insert(END, f"Installing {self.tools[tool_name]['name']}...\n")
                log_text.see(END)
                dialog.update()
                
                success, message = self.install_tool(tool_name)
                log_text.insert(END, f"  {message}\n")
                log_text.see(END)
                dialog.update()
            
            log_text.insert(END, "\nWindows tool installation complete.\n")
            log_text.insert(END, "Note: For full functionality, consider using Linux.\n")
        
        threading.Thread(target=install_windows_thread, daemon=True).start()
        
        Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)


def check_and_install_tools(parent_window=None):
    """Main function to check and install forensic tools."""
    installer = ToolInstaller(parent_window)
    installer.show_installation_dialog()


if __name__ == "__main__":
    # Test the installer
    installer = ToolInstaller()
    status = installer.get_tool_status()
    
    print("Tool Status:")
    for tool_name, info in status.items():
        print(f"  {info['name']}: {'✓' if info['available'] else '✗'}")

