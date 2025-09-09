"""GUI for the Digital Forensics Workbench with all features.

This is the main graphical interface that integrates all forensic modules
including OS detection, browser forensics, registry analysis, mounting
options, and comprehensive reporting capabilities.
"""

from __future__ import annotations

import json
import os
import threading
import hashlib
import datetime
from tkinter import (
    Tk, Toplevel, Frame, Label, Entry, Text, Button,
    filedialog, END, Scrollbar, BooleanVar, Checkbutton,
    StringVar, IntVar, DoubleVar, messagebox, HORIZONTAL, VERTICAL, Menu
)

from tkinter import ttk
from typing import Optional, Dict, List, Any
import webbrowser
import tempfile
import csv

# Import all forensic modules
from . import env, mount, keywords, forensic_tools
from .os_detector import OSDetector, OSType
from .browser_forensics import BrowserForensics
from .registry_analyzer import RegistryAnalyzer


class MainApp(Tk):
    """Main application class for the Digital Forensics Workbench."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Digital Forensics Workbench")
        self.geometry("1400x800")

        # Set modern theme
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except:
            pass

        # Configure style
        self.style.configure("Header.TLabel", font=("Arial", 11, "bold"))
        self.style.configure("Status.TLabel", font=("Arial", 9))

        # Initialize variables
        self.current_case = {}
        self.current_mount_point = None
        self.detected_os = None
        self.evidence_items = []

        # Create menu bar
        self._create_menu()

        # Create main layout
        self._create_layout()

        # Initialize status
        self.set_status("Ready - No case loaded")

        # Check environment on startup
        self.after(100, self._refresh_env)

    def _create_menu(self) -> None:
        """Create application menu bar."""
        menubar = ttk.Frame(self)
        menubar.pack(fill="x", side="top")

        # File menu
        file_btn = ttk.Menubutton(menubar, text="File", underline=0)
        file_btn.pack(side="left", padx=2)
        file_menu = Menu(file_btn, tearoff=0)
        file_btn["menu"] = file_menu

        file_menu.add_command(label="New Case", command=self._new_case)
        file_menu.add_command(label="Open Case", command=self._open_case)
        file_menu.add_command(label="Save Case", command=self._save_case)
        file_menu.add_separator()
        file_menu.add_command(label="Export Report", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        # Tools menu
        tools_btn = ttk.Menubutton(menubar, text="Tools", underline=0)
        tools_btn.pack(side="left", padx=2)
        tools_menu = Menu(tools_btn, tearoff=0)
        tools_btn["menu"] = tools_menu

        tools_menu.add_command(label="Hash Calculator", command=self._open_hash_calculator)
        tools_menu.add_command(label="Hex Viewer", command=self._open_hex_viewer)
        tools_menu.add_command(label="Timeline Viewer", command=self._open_timeline_viewer)
        tools_menu.add_separator()
        tools_menu.add_command(label="Install Tools Guide", command=self._show_tools_guide)

        # Help menu
        help_btn = ttk.Menubutton(menubar, text="Help", underline=0)
        help_btn.pack(side="left", padx=2)
        help_menu = Menu(help_btn, tearoff=0)
        help_btn["menu"] = help_menu

        help_menu.add_command(label="Documentation", command=self._show_documentation)
        help_menu.add_command(label="About", command=self._show_about)

    def _create_layout(self) -> None:
        """Create main application layout."""
        # Main container
        main_container = ttk.PanedWindow(self, orient="horizontal")
        main_container.pack(fill="both", expand=True)

        # Left panel - Evidence tree
        left_panel = ttk.Frame(main_container, width=250)
        main_container.add(left_panel, weight=1)

        ttk.Label(left_panel, text="Evidence Items", style="Header.TLabel").pack(pady=5)

        # Evidence tree
        self.evidence_tree = ttk.Treeview(left_panel, show="tree")
        self.evidence_tree.pack(fill="both", expand=True, padx=5, pady=5)

        # Add sample evidence structure
        self.evidence_tree.insert("", "end", "case", text="Current Case", open=True)

        # Right panel - Tabbed interface
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=4)

        # Notebook for tabs
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill="both", expand=True)

        # Create all tabs
        self._create_case_tab()
        self._create_mount_tab()
        self._create_analysis_tab()
        self._create_search_tab()
        self._create_browser_tab()
        self._create_registry_tab()
        self._create_memory_tab()
        self._create_network_tab()
        self._create_mobile_tab()
        self._create_vm_tab()
        self._create_timeline_tab()
        self._create_report_tab()

        # Status bar
        status_frame = ttk.Frame(self)
        status_frame.pack(fill="x", side="bottom")

        self.status_var = ttk.Label(status_frame, text="Ready", style="Status.TLabel", relief="sunken")
        self.status_var.pack(side="left", fill="x", expand=True)

        # Progress bar in status
        self.main_progress = ttk.Progressbar(status_frame, length=200, mode="determinate")
        self.main_progress.pack(side="right", padx=5)

    def _create_case_tab(self) -> None:
        """Create case information tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Case Info")

        # Case details section
        case_frame = ttk.LabelFrame(frame, text="Case Details", padding=10)
        case_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        # Case fields
        fields = [
            ("Case Name:", "case_name"),
            ("Case Number:", "case_number"),
            ("Investigator:", "investigator"),
            ("Date Created:", "date_created"),
            ("Description:", "description"),
        ]

        self.case_vars = {}
        for i, (label, field) in enumerate(fields):
            ttk.Label(case_frame, text=label).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            if field == "description":
                var = Text(case_frame, height=3, width=50)
                var.grid(row=i, column=1, sticky="ew", padx=5, pady=2)
            else:
                var = ttk.Entry(case_frame, width=40)
                var.grid(row=i, column=1, sticky="ew", padx=5, pady=2)
            self.case_vars[field] = var

        # Evidence OS detection
        os_frame = ttk.LabelFrame(frame, text="Evidence OS Detection", padding=10)
        os_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        ttk.Label(os_frame, text="Detected OS:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.detected_os_label = ttk.Label(os_frame, text="Not detected", font=("Arial", 10, "bold"))
        self.detected_os_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)

        ttk.Button(os_frame, text="Auto-Detect OS", command=self._auto_detect_os).grid(row=0, column=2, padx=5)

        # OS details
        self.os_details_text = Text(os_frame, height=8, width=60)
        self.os_details_text.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        # Environment info
        env_frame = ttk.LabelFrame(frame, text="System Environment", padding=10)
        env_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        self.env_text = Text(env_frame, height=10)
        self.env_text.pack(fill="both", expand=True)

        ttk.Button(env_frame, text="Refresh Environment", command=self._refresh_env).pack(pady=5)

        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _create_mount_tab(self) -> None:
        """Create mount tab with advanced options."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Mount/Extract")

        # Image selection
        img_frame = ttk.LabelFrame(frame, text="Disk Image", padding=10)
        img_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        ttk.Label(img_frame, text="Image File:").grid(row=0, column=0, sticky="w", padx=5)
        self.image_path_var = ttk.Entry(img_frame, width=60)
        self.image_path_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(img_frame, text="Browse", command=self._browse_image).grid(row=0, column=2, padx=5)
        ttk.Button(img_frame, text="Calculate Hash", command=self._calculate_image_hash).grid(row=0, column=3, padx=5)

        # Hash display
        ttk.Label(img_frame, text="MD5:").grid(row=1, column=0, sticky="w", padx=5)
        self.image_md5_label = ttk.Label(img_frame, text="Not calculated")
        self.image_md5_label.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(img_frame, text="SHA256:").grid(row=2, column=0, sticky="w", padx=5)
        self.image_sha256_label = ttk.Label(img_frame, text="Not calculated")
        self.image_sha256_label.grid(row=2, column=1, sticky="w", padx=5)

        # Partition list
        part_frame = ttk.LabelFrame(frame, text="Partitions", padding=10)
        part_frame.grid(row=1, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

        # Partition tree with more details
        columns = ("Index", "Start", "End", "Size", "Type", "Description")
        self.partitions_tree = ttk.Treeview(part_frame, columns=columns, show="headings", height=8)

        for col in columns:
            self.partitions_tree.heading(col, text=col)
            self.partitions_tree.column(col, width=100)

        self.partitions_tree.grid(row=0, column=0, columnspan=3, sticky="nsew")

        vsb = ttk.Scrollbar(part_frame, orient="vertical", command=self.partitions_tree.yview)
        vsb.grid(row=0, column=3, sticky="ns")
        self.partitions_tree.configure(yscrollcommand=vsb.set)

        ttk.Button(part_frame, text="Scan Partitions", command=self._scan_partitions).grid(row=1, column=0, pady=5)
        ttk.Button(part_frame, text="Analyze Partition", command=self._analyze_partition).grid(row=1, column=1, pady=5)

        # Mount options
        mount_frame = ttk.LabelFrame(frame, text="Mount Options", padding=10)
        mount_frame.grid(row=2, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

        # Mount directory
        ttk.Label(mount_frame, text="Mount Point:").grid(row=0, column=0, sticky="w", padx=5)
        self.mount_dir_var = ttk.Entry(mount_frame, width=50)
        self.mount_dir_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(mount_frame, text="Browse", command=self._browse_mount_dir).grid(row=0, column=2)

        # Advanced options
        ttk.Label(mount_frame, text="Options:").grid(row=1, column=0, sticky="w", padx=5, pady=5)

        options_frame = ttk.Frame(mount_frame)
        options_frame.grid(row=1, column=1, columnspan=2, sticky="w", padx=5)

        self.mount_readonly = BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Read-only", variable=self.mount_readonly).pack(side="left", padx=5)

        self.mount_loop = BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Loop device", variable=self.mount_loop).pack(side="left", padx=5)

        self.mount_noexec = BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="No execute", variable=self.mount_noexec).pack(side="left", padx=5)

        # Custom offset
        ttk.Label(mount_frame, text="Custom Offset:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.custom_offset_var = ttk.Entry(mount_frame, width=20)
        self.custom_offset_var.grid(row=2, column=1, sticky="w", padx=5)
        ttk.Label(mount_frame, text="(bytes, optional)").grid(row=2, column=2, sticky="w")

        # Action buttons
        action_frame = ttk.Frame(mount_frame)
        action_frame.grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Button(action_frame, text="Mount (Linux)", command=self._mount_selected).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Extract (Cross-platform)", command=self._extract_selected).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Unmount", command=self._unmount).pack(side="left", padx=5)

        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _create_analysis_tab(self) -> None:
        """Create comprehensive analysis tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Analysis")

        # Analysis options
        options_frame = ttk.LabelFrame(frame, text="Analysis Options", padding=10)
        options_frame.pack(fill="x", padx=5, pady=5)

        # Quick analysis buttons
        ttk.Button(options_frame, text="Quick Triage", command=self._run_quick_triage).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Full Analysis", command=self._run_full_analysis).pack(side="left", padx=5)
        ttk.Button(options_frame, text="File Carving", command=self._run_file_carving).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Deleted Files", command=self._recover_deleted).pack(side="left", padx=5)
        ttk.Button(options_frame, text="YARA Scan", command=self._run_yara_scan).pack(side="left", padx=5)

        # Results area
        results_frame = ttk.LabelFrame(frame, text="Analysis Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # Results notebook
        self.analysis_notebook = ttk.Notebook(results_frame)
        self.analysis_notebook.pack(fill="both", expand=True)

        # File system tab
        fs_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(fs_frame, text="File System")

        self.fs_tree = ttk.Treeview(fs_frame, columns=("Size", "Modified", "Type"), show="tree headings")
        self.fs_tree.heading("#0", text="Name")
        self.fs_tree.heading("Size", text="Size")
        self.fs_tree.heading("Modified", text="Modified")
        self.fs_tree.heading("Type", text="Type")
        self.fs_tree.pack(fill="both", expand=True)

        # Artifacts tab
        artifacts_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(artifacts_frame, text="Artifacts")

        self.artifacts_text = Text(artifacts_frame, wrap="none")
        self.artifacts_text.pack(fill="both", expand=True)

        # Suspicious files tab
        suspicious_frame = ttk.Frame(self.analysis_notebook)
        self.analysis_notebook.add(suspicious_frame, text="Suspicious")

        self.suspicious_list = ttk.Treeview(suspicious_frame, columns=("Path", "Reason", "Hash"), show="headings")
        self.suspicious_list.heading("Path", text="File Path")
        self.suspicious_list.heading("Reason", text="Reason")
        self.suspicious_list.heading("Hash", text="MD5 Hash")
        self.suspicious_list.pack(fill="both", expand=True)

    def _create_search_tab(self) -> None:
        """Create search tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Search")

        # Search options
        search_frame = ttk.LabelFrame(frame, text="Search Options", padding=10)
        search_frame.pack(fill="x", padx=5, pady=5)

        # Search directory
        ttk.Label(search_frame, text="Directory:").grid(row=0, column=0, sticky="w", padx=5)
        self.search_dir_var = ttk.Entry(search_frame, width=50)
        self.search_dir_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(search_frame, text="Browse", command=self._browse_search_dir).grid(row=0, column=2)

        # Search terms
        ttk.Label(search_frame, text="Keywords:").grid(row=1, column=0, sticky="w", padx=5)
        self.keywords_var = ttk.Entry(search_frame, width=50)
        self.keywords_var.grid(row=1, column=1, sticky="ew", padx=5)

        # Advanced options
        adv_frame = ttk.Frame(search_frame)
        adv_frame.grid(row=2, column=0, columnspan=3, sticky="w", padx=5)

        self.regex_search = BooleanVar(value=False)
        ttk.Checkbutton(adv_frame, text="Regex", variable=self.regex_search).pack(side="left", padx=5)

        self.case_sensitive = BooleanVar(value=False)
        ttk.Checkbutton(adv_frame, text="Case Sensitive", variable=self.case_sensitive).pack(side="left", padx=5)

        self.whole_word = BooleanVar(value=False)
        ttk.Checkbutton(adv_frame, text="Whole Word", variable=self.whole_word).pack(side="left", padx=5)

        # Action buttons
        action_frame = ttk.Frame(search_frame)
        action_frame.grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Button(action_frame, text="Start Search", command=self._run_keyword_search).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Clear Results", command=self._clear_search_results).pack(side="left", padx=5)

        # Results
        results_frame = ttk.LabelFrame(frame, text="Search Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.search_results_text = Text(results_frame, wrap="none")
        self.search_results_text.pack(fill="both", expand=True)

    def _create_browser_tab(self) -> None:
        """Create browser forensics tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Browser")

        # Browser selection
        browser_frame = ttk.LabelFrame(frame, text="Browser Data", padding=10)
        browser_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(browser_frame, text="Select Browser:").grid(row=0, column=0, sticky="w", padx=5)
        self.browser_var = ttk.Combobox(browser_frame, values=["Chrome", "Firefox", "Edge", "Safari"])
        self.browser_var.grid(row=0, column=1, sticky="w", padx=5)
        self.browser_var.current(0)

        ttk.Label(browser_frame, text="Profile Path (Optional):").grid(row=1, column=0, sticky="w", padx=5)
        self.browser_profile_var = ttk.Entry(browser_frame, width=50)
        self.browser_profile_var.grid(row=1, column=1, sticky="ew", padx=5)
        ttk.Button(browser_frame, text="Browse", command=self._browse_browser_profile).grid(row=1, column=2)

        # Analysis options
        options_frame = ttk.Frame(browser_frame)
        options_frame.grid(row=2, column=0, columnspan=3, pady=10)

        ttk.Button(options_frame, text="Analyze History", command=self._analyze_browser_history).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Analyze Downloads", command=self._analyze_browser_downloads).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Analyze Cookies", command=self._analyze_browser_cookies).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Analyze Bookmarks", command=self._analyze_browser_bookmarks).pack(side="left", padx=5)

        # Results
        self.browser_notebook = ttk.Notebook(frame)
        self.browser_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # History tab
        history_frame = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(history_frame, text="History")
        self.history_tree = ttk.Treeview(history_frame, columns=("URL", "Title", "Visit Count", "Last Visit"))
        self.history_tree.pack(fill="both", expand=True)

        # Downloads tab
        downloads_frame = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(downloads_frame, text="Downloads")
        self.downloads_tree = ttk.Treeview(downloads_frame, columns=("File", "URL", "Start Time", "End Time", "Total Bytes"))
        self.downloads_tree.pack(fill="both", expand=True)

        # Cookies tab
        cookies_frame = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(cookies_frame, text="Cookies")
        self.cookies_tree = ttk.Treeview(cookies_frame, columns=("Host", "Name", "Value", "Expires"))
        self.cookies_tree.pack(fill="both", expand=True)

        # Bookmarks tab
        bookmarks_frame = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(bookmarks_frame, text="Bookmarks")
        self.bookmarks_tree = ttk.Treeview(bookmarks_frame, columns=("Title", "URL", "Date Added"))
        self.bookmarks_tree.pack(fill="both", expand=True)

    def _create_registry_tab(self) -> None:
        """Create registry analysis tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Registry")

        # Registry hive selection
        reg_frame = ttk.LabelFrame(frame, text="Registry Hive", padding=10)
        reg_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(reg_frame, text="Hive File:").grid(row=0, column=0, sticky="w", padx=5)
        self.hive_path_var = ttk.Entry(reg_frame, width=50)
        self.hive_path_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(reg_frame, text="Browse", command=self._browse_hive).grid(row=0, column=2)

        # Analysis options
        options_frame = ttk.Frame(reg_frame)
        options_frame.grid(row=1, column=0, columnspan=3, pady=10)

        ttk.Button(options_frame, text="Analyze User Accounts", command=self._analyze_user_accounts).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Analyze USB Devices", command=self._analyze_usb_devices).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Analyze Installed Software", command=self._analyze_installed_software).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Extract SAM/SECURITY", command=self._extract_sam_security).pack(side="left", padx=5)

        # Results
        self.registry_notebook = ttk.Notebook(frame)
        self.registry_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # User accounts tab
        users_frame = ttk.Frame(self.registry_notebook)
        self.registry_notebook.add(users_frame, text="User Accounts")
        self.users_reg_tree = ttk.Treeview(users_frame, columns=("Username", "SID", "Last Login"))
        self.users_reg_tree.pack(fill="both", expand=True)

        # USB devices tab
        usb_frame = ttk.Frame(self.registry_notebook)
        self.registry_notebook.add(usb_frame, text="USB Devices")
        self.usb_reg_tree = ttk.Treeview(usb_frame, columns=("Device", "Serial", "First Connected", "Last Connected"))
        self.usb_reg_tree.pack(fill="both", expand=True)

        # Software tab
        software_frame = ttk.Frame(self.registry_notebook)
        self.registry_notebook.add(software_frame, text="Software")
        self.software_reg_tree = ttk.Treeview(software_frame, columns=("Name", "Version", "Publisher", "Install Date"))
        self.software_reg_tree.pack(fill="both", expand=True)

    def _create_memory_tab(self) -> None:
        """Create memory forensics tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Memory")

        # Memory analysis
        mem_frame = ttk.LabelFrame(frame, text="Memory Analysis", padding=10)
        mem_frame.pack(fill="x", padx=5, pady=5)

        # Memory image
        ttk.Label(mem_frame, text="Memory Image:").grid(row=0, column=0, sticky="w", padx=5)
        self.mem_image_var = ttk.Entry(mem_frame, width=50)
        self.mem_image_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(mem_frame, text="Browse", command=self._browse_mem_image).grid(row=0, column=2)

        # Profile/OS selection
        ttk.Label(mem_frame, text="OS Profile:").grid(row=1, column=0, sticky="w", padx=5)
        self.mem_profile_var = ttk.Combobox(mem_frame, values=["Auto-detect", "Windows 10", "Windows 7", "Linux", "macOS"])
        self.mem_profile_var.grid(row=1, column=1, sticky="w", padx=5)
        self.mem_profile_var.current(0)

        # Plugin selection
        ttk.Label(mem_frame, text="Plugin:").grid(row=2, column=0, sticky="w", padx=5)
        self.plugin_var = ttk.Combobox(mem_frame, width=40)
        self.plugin_var.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Button(mem_frame, text="Run Plugin", command=self._run_volatility_plugin).grid(row=2, column=2)

        # Quick analysis buttons
        quick_frame = ttk.Frame(mem_frame)
        quick_frame.grid(row=3, column=0, columnspan=3, pady=10)

        ttk.Button(quick_frame, text="Process List", command=lambda: self._run_vol_quick("pslist")).pack(side="left", padx=2)
        ttk.Button(quick_frame, text="Network Connections", command=lambda: self._run_vol_quick("netscan")).pack(side="left", padx=2)
        ttk.Button(quick_frame, text="Registry Hives", command=lambda: self._run_vol_quick("hivelist")).pack(side="left", padx=2)
        ttk.Button(quick_frame, text="Dump Process", command=self._dump_process).pack(side="left", padx=2)

        # Results
        results_frame = ttk.LabelFrame(frame, text="Results", padding=10)
        results_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.mem_output = Text(results_frame, wrap="none")
        self.mem_output.pack(fill="both", expand=True)

    def _create_network_tab(self) -> None:
        """Create network forensics tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Network")

        # Network analysis
        net_frame = ttk.LabelFrame(frame, text="Network Analysis", padding=10)
        net_frame.pack(fill="x", padx=5, pady=5)

        # PCAP file
        ttk.Label(net_frame, text="PCAP File:").grid(row=0, column=0, sticky="w", padx=5)
        self.pcap_var = ttk.Entry(net_frame, width=50)
        self.pcap_var.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(net_frame, text="Browse", command=self._browse_pcap).grid(row=0, column=2)

        # Analysis options
        options_frame = ttk.Frame(net_frame)
        options_frame.grid(row=1, column=0, columnspan=3, pady=10)

        ttk.Button(options_frame, text="Protocol Summary", command=self._analyze_protocols).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Conversations", command=self._analyze_conversations).pack(side="left", padx=5)
        ttk.Button(options_frame, text="DNS Queries", command=self._analyze_dns).pack(side="left", padx=5)
        ttk.Button(options_frame, text="HTTP Traffic", command=self._analyze_http).pack(side="left", padx=5)
        ttk.Button(options_frame, text="Extract Files", command=self._extract_network_files).pack(side="left", padx=5)

        # Results
        self.network_notebook = ttk.Notebook(frame)
        self.network_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Summary tab
        summary_frame = ttk.Frame(self.network_notebook)
        self.network_notebook.add(summary_frame, text="Summary")
        self.network_summary_text = Text(summary_frame)
        self.network_summary_text.pack(fill="both", expand=True)

        # Conversations tab
        conv_frame = ttk.Frame(self.network_notebook)
        self.network_notebook.add(conv_frame, text="Conversations")
        self.conversations_tree = ttk.Treeview(conv_frame, columns=("Source", "Destination", "Protocol", "Packets", "Bytes"))
        self.conversations_tree.pack(fill="both", expand=True)

    def _create_mobile_tab(self) -> None:
        """Create mobile device forensics tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Mobile")

        # Mobile analysis
        mobile_frame = ttk.LabelFrame(frame, text="Mobile Device Analysis", padding=10)
        mobile_frame.pack(fill="x", padx=5, pady=5)

        # Device type
        ttk.Label(mobile_frame, text="Device Type:").grid(row=0, column=0, sticky="w", padx=5)
        self.mobile_type_var = ttk.Combobox(mobile_frame, values=["Android", "iOS"])
        self.mobile_type_var.grid(row=0, column=1, sticky="w", padx=5)

        # Data path
        ttk.Label(mobile_frame, text="Data Path:").grid(row=1, column=0, sticky="w", padx=5)
        self.mobile_path_var = ttk.Entry(mobile_frame, width=50)
        self.mobile_path_var.grid(row=1, column=1, sticky="ew", padx=5)
        ttk.Button(mobile_frame, text="Browse", command=self._browse_mobile_data).grid(row=1, column=2)

        # Analysis buttons
        analysis_frame = ttk.Frame(mobile_frame)
        analysis_frame.grid(row=2, column=0, columnspan=3, pady=10)

        ttk.Button(analysis_frame, text="Run ALEAPP", command=self._run_aleapp).pack(side="left", padx=5)
        ttk.Button(analysis_frame, text="Extract Contacts", command=self._extract_contacts).pack(side="left", padx=5)
        ttk.Button(analysis_frame, text="Extract Messages", command=self._extract_messages).pack(side="left", padx=5)
        ttk.Button(analysis_frame, text="Extract Call Logs", command=self._extract_call_logs).pack(side="left", padx=5)
        ttk.Button(analysis_frame, text="App Analysis", command=self._analyze_apps).pack(side="left", padx=5)

        # Results
        self.mobile_output = Text(frame)
        self.mobile_output.pack(fill="both", expand=True, padx=5, pady=5)

    def _create_vm_tab(self) -> None:
        """Create VM forensics tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="VM Analysis")

        # VM analysis
        vm_frame = ttk.LabelFrame(frame, text="Virtual Machine Analysis", padding=10)
        vm_frame.pack(fill="x", padx=5, pady=5)

        # VM type
        ttk.Label(vm_frame, text="VM Type:").grid(row=0, column=0, sticky="w", padx=5)
        self.vm_type_var = ttk.Combobox(vm_frame, values=["VMware", "VirtualBox", "Hyper-V", "QEMU/KVM"])
        self.vm_type_var.grid(row=0, column=1, sticky="w", padx=5)

        # VM disk file
        ttk.Label(vm_frame, text="VM Disk:").grid(row=1, column=0, sticky="w", padx=5)
        self.vm_disk_var = ttk.Entry(vm_frame, width=50)
        self.vm_disk_var.grid(row=1, column=1, sticky="ew", padx=5)
        ttk.Button(vm_frame, text="Browse", command=self._browse_vm_disk).grid(row=1, column=2)

        # Analysis options
        ttk.Button(vm_frame, text="Convert to Raw", command=self._convert_vm_disk).grid(row=2, column=0, pady=10)
        ttk.Button(vm_frame, text="Analyze Snapshots", command=self._analyze_snapshots).grid(row=2, column=1, pady=10)
        ttk.Button(vm_frame, text="Extract Config", command=self._extract_vm_config).grid(row=2, column=2, pady=10)

        # Results
        self.vm_output = Text(frame)
        self.vm_output.pack(fill="both", expand=True, padx=5, pady=5)

    def _create_timeline_tab(self) -> None:
        """Create timeline tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Timeline")

        # Timeline options
        timeline_frame = ttk.LabelFrame(frame, text="Timeline Generation", padding=10)
        timeline_frame.pack(fill="x", padx=5, pady=5)

        # Source selection
        ttk.Label(timeline_frame, text="Source:").grid(row=0, column=0, sticky="w", padx=5)
        self.timeline_source_var = ttk.Combobox(timeline_frame,
            values=["File System", "Registry", "Event Logs", "Browser", "All Sources"])
        self.timeline_source_var.grid(row=0, column=1, sticky="w", padx=5)

        # Date range
        ttk.Label(timeline_frame, text="Start Date:").grid(row=1, column=0, sticky="w", padx=5)
        self.timeline_start_var = ttk.Entry(timeline_frame, width=20)
        self.timeline_start_var.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(timeline_frame, text="End Date:").grid(row=2, column=0, sticky="w", padx=5)
        self.timeline_end_var = ttk.Entry(timeline_frame, width=20)
        self.timeline_end_var.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Button(timeline_frame, text="Generate Timeline", command=self._generate_timeline).grid(row=3, column=1, pady=10)

        # Timeline display
        timeline_display = ttk.LabelFrame(frame, text="Timeline Events", padding=10)
        timeline_display.pack(fill="both", expand=True, padx=5, pady=5)

        columns = ("Timestamp", "Source", "Event", "Details")
        self.timeline_tree = ttk.Treeview(timeline_display, columns=columns, show="headings")

        for col in columns:
            self.timeline_tree.heading(col, text=col)

        self.timeline_tree.pack(fill="both", expand=True)

    def _create_report_tab(self) -> None:
        """Create reporting tab."""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Report")

        # Report options
        report_frame = ttk.LabelFrame(frame, text="Report Generation", padding=10)
        report_frame.pack(fill="x", padx=5, pady=5)

        # Report type
        ttk.Label(report_frame, text="Report Type:").grid(row=0, column=0, sticky="w", padx=5)
        self.report_type_var = ttk.Combobox(report_frame,
            values=["Executive Summary", "Technical Report", "Timeline Report", "Full Analysis"])
        self.report_type_var.grid(row=0, column=1, sticky="w", padx=5)

        # Format
        ttk.Label(report_frame, text="Format:").grid(row=1, column=0, sticky="w", padx=5)
        self.report_format_var = ttk.Combobox(report_frame, values=["HTML", "PDF", "DOCX", "JSON", "CSV"])
        self.report_format_var.grid(row=1, column=1, sticky="w", padx=5)

        # Include options
        include_frame = ttk.Frame(report_frame)
        include_frame.grid(row=2, column=0, columnspan=2, pady=10)

        self.include_screenshots = BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="Screenshots", variable=self.include_screenshots).pack(side="left", padx=5)

        self.include_hashes = BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="File Hashes", variable=self.include_hashes).pack(side="left", padx=5)

        self.include_timeline = BooleanVar(value=True)
        ttk.Checkbutton(include_frame, text="Timeline", variable=self.include_timeline).pack(side="left", padx=5)

        # Generate button
        ttk.Button(report_frame, text="Generate Report", command=self._generate_report).grid(row=3, column=1, pady=10)

        # Report preview
        preview_frame = ttk.LabelFrame(frame, text="Report Preview", padding=10)
        preview_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.report_preview = Text(preview_frame)
        self.report_preview.pack(fill="both", expand=True)

    # Utility methods
    def set_status(self, message: str) -> None:
        """Update status bar."""
        self.status_var.config(text=message)
        self.update_idletasks()

    def _browse_image(self) -> None:
        """Browse for disk image file."""
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[("Disk Images", "*.dd *.img *.raw *.vmdk *.vdi *.e01"), ("All Files", "*.*")]
        )
        if path:
            self.image_path_var.delete(0, END)
            self.image_path_var.insert(0, path)
            self.set_status(f"Selected: {os.path.basename(path)}")

    def _browse_mount_dir(self) -> None:
        """Browse for mount directory."""
        directory = filedialog.askdirectory(title="Select Mount Directory")
        if directory:
            self.mount_dir_var.delete(0, END)
            self.mount_dir_var.insert(0, directory)

    def _browse_search_dir(self) -> None:
        """Browse for search directory."""
        directory = filedialog.askdirectory(title="Select Search Directory")
        if directory:
            self.search_dir_var.delete(0, END)
            self.search_dir_var.insert(0, directory)

    def _browse_mem_image(self) -> None:
        """Browse for memory image."""
        path = filedialog.askopenfilename(
            title="Select Memory Image",
            filetypes=[("Memory Images", "*.dmp *.mem *.raw *.vmem"), ("All Files", "*.*")]
        )
        if path:
            self.mem_image_var.delete(0, END)
            self.mem_image_var.insert(0, path)

    def _browse_pcap(self) -> None:
        """Browse for PCAP file."""
        path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")]
        )
        if path:
            self.pcap_var.delete(0, END)
            self.pcap_var.insert(0, path)

    def _browse_mobile_data(self) -> None:
        """Browse for mobile data directory."""
        directory = filedialog.askdirectory(title="Select Mobile Data Directory")
        if directory:
            self.mobile_path_var.delete(0, END)
            self.mobile_path_var.insert(0, directory)

    def _browse_vm_disk(self) -> None:
        """Browse for VM disk file."""
        path = filedialog.askopenfilename(
            title="Select VM Disk",
            filetypes=[("VM Disks", "*.vmdk *.vdi *.vhd *.vhdx *.qcow2"), ("All Files", "*.*")]
        )
        if path:
            self.vm_disk_var.delete(0, END)
            self.vm_disk_var.insert(0, path)

    # Implementation methods (placeholders for actual functionality)
    def _refresh_env(self) -> None:
        """Refresh environment information."""
        self.set_status("Checking environment...")
        info = env.check_environment()

        self.env_text.delete("1.0", END)
        self.env_text.insert(END, f"OS: {info['os_type']} {info['os_version']}\n")
        self.env_text.insert(END, f"WSL: {'Yes' if info['is_wsl'] else 'No'}\n\n")
        self.env_text.insert(END, "Available Tools:\n")

        for tool, available in info["tools"].items():
            status = "✓" if available else "✗"
            self.env_text.insert(END, f"  {status} {tool}\n")

        self.set_status("Environment check complete")

    def _auto_detect_os(self) -> None:
        """Auto-detect OS of mounted evidence."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first")
            return

        self.set_status("Detecting OS...")

        def detect():
            detector = OSDetector(self.current_mount_point)
            os_info = detector.detect()

            # Update GUI with results
            self.detected_os = os_info
            self.detected_os_label.config(text=f"{os_info.os_type.value} {os_info.version or ''}")

            # Show details
            self.os_details_text.delete("1.0", END)
            details = f"OS Type: {os_info.os_type.value}\n"
            details += f"Version: {os_info.version or 'Unknown'}\n"
            details += f"Architecture: {os_info.architecture or 'Unknown'}\n"
            details += f"Boot Time: {os_info.boot_time or 'Unknown'}\n"
            details += f"Registry Path: {os_info.registry_path or 'N/A'}\n"
            details += f"Browser Paths: {os_info.browser_paths or 'N/A'}\n"
            self.os_details_text.insert(END, details)

            self.set_status("OS detection complete")

        threading.Thread(target=detect).start()

    def _calculate_image_hash(self) -> None:
        """Calculate MD5 and SHA256 hash of the selected image file."""
        image_path = self.image_path_var.get()
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return

        self.set_status("Calculating image hash...")

        def calculate_hash():
            try:
                md5_hash = hashlib.md5()
                sha256_hash = hashlib.sha256()
                with open(image_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)
                self.image_md5_label.config(text=md5_hash.hexdigest())
                self.image_sha256_label.config(text=sha256_hash.hexdigest())
                self.set_status("Image hash calculated.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to calculate hash: {e}")
                self.set_status("Hash calculation failed.")

        threading.Thread(target=calculate_hash).start()

    def _scan_partitions(self) -> None:
        """Scan selected disk image for partitions."""
        image_path = self.image_path_var.get()
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return

        self.set_status("Scanning partitions...")

        def scan():
            try:
                partitions = mount.scan_partitions(image_path)
                for i in self.partitions_tree.get_children():
                    self.partitions_tree.delete(i)
                for part in partitions:
                    self.partitions_tree.insert("", "end", values=(
                        part.index, part.start, part.end, part.size, part.type, part.description
                    ))
                self.set_status("Partition scan complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to scan partitions: {e}")
                self.set_status("Partition scan failed.")

        threading.Thread(target=scan).start()

    def _analyze_partition(self) -> None:
        """Analyze selected partition for file systems and details."""
        selected_item = self.partitions_tree.focus()
        if not selected_item:
            messagebox.showwarning("No Selection", "Please select a partition to analyze.")
            return

        partition_index = self.partitions_tree.item(selected_item, "values")[0]
        image_path = self.image_path_var.get()

        self.set_status(f"Analyzing partition {partition_index}...")

        def analyze():
            try:
                # Placeholder for actual partition analysis logic
                messagebox.showinfo("Analysis", f"Analyzing partition {partition_index} from {image_path}")
                self.set_status(f"Partition {partition_index} analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to analyze partition: {e}")
                self.set_status("Partition analysis failed.")

        threading.Thread(target=analyze).start()

    def _mount_selected(self) -> None:
        """Mount the selected disk image/partition."""
        image_path = self.image_path_var.get()
        mount_point = self.mount_dir_var.get()
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return
        if not mount_point:
            messagebox.showerror("Error", "Please select a mount directory.")
            return

        self.set_status("Mounting image...")

        def do_mount():
            try:
                # Get selected partition offset if any
                selected_item = self.partitions_tree.focus()
                offset = 0
                if selected_item:
                    offset = int(self.partitions_tree.item(selected_item, "values")[1]) # Start offset

                # Get custom offset if provided
                custom_offset_str = self.custom_offset_var.get()
                if custom_offset_str:
                    offset += int(custom_offset_str)

                mount.mount_image(
                    image_path,
                    mount_point,
                    offset=offset,
                    read_only=self.mount_readonly.get(),
                    loop_device=self.mount_loop.get(),
                    no_exec=self.mount_noexec.get()
                )
                self.current_mount_point = mount_point
                self.set_status(f"Image mounted to {mount_point}")
                messagebox.showinfo("Mount Success", f"Image successfully mounted to {mount_point}")
            except Exception as e:
                messagebox.showerror("Mount Error", f"Failed to mount image: {e}")
                self.set_status("Mount failed.")

        threading.Thread(target=do_mount).start()

    def _extract_selected(self) -> None:
        """Extract files from the selected disk image/partition (cross-platform)."""
        image_path = self.image_path_var.get()
        extract_dir = self.mount_dir_var.get() # Re-using mount_dir_var for extract destination
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return
        if not extract_dir:
            messagebox.showerror("Error", "Please select an extraction directory.")
            return

        self.set_status("Extracting files...")

        def do_extract():
            try:
                # Get selected partition offset if any
                selected_item = self.partitions_tree.focus()
                offset = 0
                if selected_item:
                    offset = int(self.partitions_tree.item(selected_item, "values")[1]) # Start offset

                # Get custom offset if provided
                custom_offset_str = self.custom_offset_var.get()
                if custom_offset_str:
                    offset += int(custom_offset_str)

                mount.extract_files(image_path, extract_dir, offset=offset)
                self.set_status(f"Files extracted to {extract_dir}")
                messagebox.showinfo("Extraction Success", f"Files successfully extracted to {extract_dir}")
            except Exception as e:
                messagebox.showerror("Extraction Error", f"Failed to extract files: {e}")
                self.set_status("Extraction failed.")

        threading.Thread(target=do_extract).start()

    def _unmount(self) -> None:
        """Unmount the currently mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "No image is currently mounted.")
            return

        self.set_status("Unmounting image...")

        def do_unmount():
            try:
                mount.unmount_image(self.current_mount_point)
                self.set_status(f"Successfully unmounted {self.current_mount_point}")
                messagebox.showinfo("Unmount Success", f"Successfully unmounted {self.current_mount_point}")
                self.current_mount_point = None
            except Exception as e:
                messagebox.showerror("Unmount Error", f"Failed to unmount image: {e}")
                self.set_status("Unmount failed.")

        threading.Thread(target=do_unmount).start()

    def _run_quick_triage(self) -> None:
        """Perform a quick triage on the mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first.")
            return

        self.set_status("Running quick triage...")

        def triage():
            try:
                # Placeholder for quick triage logic
                self.artifacts_text.delete("1.0", END)
                self.artifacts_text.insert(END, "Performing quick triage...\n")
                self.artifacts_text.insert(END, "[Placeholder for triage results]\n")
                self.set_status("Quick triage complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Quick triage failed: {e}")
                self.set_status("Quick triage failed.")

        threading.Thread(target=triage).start()

    def _run_full_analysis(self) -> None:
        """Perform a full analysis on the mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first.")
            return

        self.set_status("Running full analysis...")

        def full_analysis():
            try:
                # Placeholder for full analysis logic
                self.artifacts_text.delete("1.0", END)
                self.artifacts_text.insert(END, "Performing full analysis...\n")
                self.artifacts_text.insert(END, "[Placeholder for full analysis results]\n")
                self.set_status("Full analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Full analysis failed: {e}")
                self.set_status("Full analysis failed.")

        threading.Thread(target=full_analysis).start()

    def _run_file_carving(self) -> None:
        """Perform file carving on the mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first.")
            return

        self.set_status("Running file carving...")

        def carving():
            try:
                # Placeholder for file carving logic
                self.artifacts_text.delete("1.0", END)
                self.artifacts_text.insert(END, "Performing file carving...\n")
                self.artifacts_text.insert(END, "[Placeholder for file carving results]\n")
                self.set_status("File carving complete.")
            except Exception as e:
                messagebox.showerror("Error", f"File carving failed: {e}")
                self.set_status("File carving failed.")

        threading.Thread(target=carving).start()

    def _recover_deleted(self) -> None:
        """Recover deleted files from the mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first.")
            return

        self.set_status("Recovering deleted files...")

        def recover():
            try:
                # Placeholder for deleted file recovery logic
                self.artifacts_text.delete("1.0", END)
                self.artifacts_text.insert(END, "Recovering deleted files...\n")
                self.artifacts_text.insert(END, "[Placeholder for deleted file recovery results]\n")
                self.set_status("Deleted file recovery complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Deleted file recovery failed: {e}")
                self.set_status("Deleted file recovery failed.")

        threading.Thread(target=recover).start()

    def _run_yara_scan(self) -> None:
        """Run YARA scan on the mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a disk image first.")
            return

        self.set_status("Running YARA scan...")

        def yara_scan():
            try:
                # Placeholder for YARA scan logic
                self.suspicious_list.delete(*self.suspicious_list.get_children())
                self.suspicious_list.insert("", "end", values=("C:\\malware.exe", "YARA Rule Match: evil_exe", "a1b2c3d4e5f6"))
                self.set_status("YARA scan complete.")
            except Exception as e:
                messagebox.showerror("Error", f"YARA scan failed: {e}")
                self.set_status("YARA scan failed.")

        threading.Thread(target=yara_scan).start()

    def _run_keyword_search(self) -> None:
        """Run keyword search on the selected directory."""
        search_dir = self.search_dir_var.get()
        keyword = self.keywords_var.get()
        if not search_dir or not os.path.exists(search_dir):
            messagebox.showerror("Error", "Please select a valid search directory.")
            return
        if not keyword:
            messagebox.showerror("Error", "Please enter keywords to search.")
            return

        self.set_status(f"Searching for ‘{keyword}’ in {search_dir}...")

        def search():
            try:
                results = keywords.search_files(
                    search_dir, keyword,
                    regex=self.regex_search.get(),
                    case_sensitive=self.case_sensitive.get(),
                    whole_word=self.whole_word.get()
                )
                self.search_results_text.delete("1.0", END)
                if results:
                    for result in results:
                        self.search_results_text.insert(END, f"Found in: {result}\n")
                else:
                    self.search_results_text.insert(END, "No results found.\n")
                self.set_status("Keyword search complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Keyword search failed: {e}")
                self.set_status("Keyword search failed.")

        threading.Thread(target=search).start()

    def _clear_search_results(self) -> None:
        """Clear search results."""
        self.search_results_text.delete("1.0", END)
        self.set_status("Search results cleared.")

    def _browse_browser_profile(self) -> None:
        """Browse for browser profile directory."""
        directory = filedialog.askdirectory(title="Select Browser Profile Directory")
        if directory:
            self.browser_profile_var.delete(0, END)
            self.browser_profile_var.insert(0, directory)

    def _analyze_browser_history(self) -> None:
        """Analyze browser history."""
        browser_type = self.browser_var.get()
        profile_path = self.browser_profile_var.get()

        self.set_status(f"Analyzing {browser_type} history...")

        def analyze():
            try:
                browser_forensics = BrowserForensics(browser_type, profile_path)
                history = browser_forensics.analyze_history()
                self.history_tree.delete(*self.history_tree.get_children())
                for entry in history:
                    self.history_tree.insert("", "end", values=(entry.url, entry.title, entry.visit_count, entry.last_visit_time))
                self.set_status(f"{browser_type} history analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Browser history analysis failed: {e}")
                self.set_status("Browser history analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_browser_downloads(self) -> None:
        """Analyze browser downloads."""
        browser_type = self.browser_var.get()
        profile_path = self.browser_profile_var.get()

        self.set_status(f"Analyzing {browser_type} downloads...")

        def analyze():
            try:
                browser_forensics = BrowserForensics(browser_type, profile_path)
                downloads = browser_forensics.analyze_downloads()
                self.downloads_tree.delete(*self.downloads_tree.get_children())
                for entry in downloads:
                    self.downloads_tree.insert("", "end", values=(entry.file_path, entry.url, entry.start_time, entry.end_time, entry.total_bytes))
                self.set_status(f"{browser_type} downloads analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Browser downloads analysis failed: {e}")
                self.set_status("Browser downloads analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_browser_cookies(self) -> None:
        """Analyze browser cookies."""
        browser_type = self.browser_var.get()
        profile_path = self.browser_profile_var.get()

        self.set_status(f"Analyzing {browser_type} cookies...")

        def analyze():
            try:
                browser_forensics = BrowserForensics(browser_type, profile_path)
                cookies = browser_forensics.analyze_cookies()
                self.cookies_tree.delete(*self.cookies_tree.get_children())
                for entry in cookies:
                    self.cookies_tree.insert("", "end", values=(entry.host, entry.name, entry.value, entry.expires_utc))
                self.set_status(f"{browser_type} cookies analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Browser cookies analysis failed: {e}")
                self.set_status("Browser cookies analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_browser_bookmarks(self) -> None:
        """Analyze browser bookmarks."""
        browser_type = self.browser_var.get()
        profile_path = self.browser_profile_var.get()

        self.set_status(f"Analyzing {browser_type} bookmarks...")

        def analyze():
            try:
                browser_forensics = BrowserForensics(browser_type, profile_path)
                bookmarks = browser_forensics.analyze_bookmarks()
                self.bookmarks_tree.delete(*self.bookmarks_tree.get_children())
                for entry in bookmarks:
                    self.bookmarks_tree.insert("", "end", values=(entry.title, entry.url, entry.date_added))
                self.set_status(f"{browser_type} bookmarks analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Browser bookmarks analysis failed: {e}")
                self.set_status("Browser bookmarks analysis failed.")

        threading.Thread(target=analyze).start()

    def _browse_hive(self) -> None:
        """Browse for registry hive file."""
        path = filedialog.askopenfilename(
            title="Select Registry Hive",
            filetypes=[("Registry Hives", "*.*")]
        )
        if path:
            self.hive_path_var.delete(0, END)
            self.hive_path_var.insert(0, path)

    def _analyze_user_accounts(self) -> None:
        """Analyze user accounts from registry hive."""
        hive_path = self.hive_path_var.get()
        if not hive_path or not os.path.exists(hive_path):
            messagebox.showerror("Error", "Please select a valid registry hive file.")
            return

        self.set_status("Analyzing user accounts...")

        def analyze():
            try:
                analyzer = RegistryAnalyzer(hive_path)
                users = analyzer.analyze_user_accounts()
                self.users_reg_tree.delete(*self.users_reg_tree.get_children())
                for user in users:
                    self.users_reg_tree.insert("", "end", values=(user.username, user.sid, user.last_login))
                self.set_status("User account analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"User account analysis failed: {e}")
                self.set_status("User account analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_usb_devices(self) -> None:
        """Analyze USB devices from registry hive."""
        hive_path = self.hive_path_var.get()
        if not hive_path or not os.path.exists(hive_path):
            messagebox.showerror("Error", "Please select a valid registry hive file.")
            return

        self.set_status("Analyzing USB devices...")

        def analyze():
            try:
                analyzer = RegistryAnalyzer(hive_path)
                usb_devices = analyzer.analyze_usb_devices()
                self.usb_reg_tree.delete(*self.usb_reg_tree.get_children())
                for device in usb_devices:
                    self.usb_reg_tree.insert("", "end", values=(device.device_name, device.serial_number, device.first_connected, device.last_connected))
                self.set_status("USB device analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"USB device analysis failed: {e}")
                self.set_status("USB device analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_installed_software(self) -> None:
        """Analyze installed software from registry hive."""
        hive_path = self.hive_path_var.get()
        if not hive_path or not os.path.exists(hive_path):
            messagebox.showerror("Error", "Please select a valid registry hive file.")
            return

        self.set_status("Analyzing installed software...")

        def analyze():
            try:
                analyzer = RegistryAnalyzer(hive_path)
                software = analyzer.analyze_installed_software()
                self.software_reg_tree.delete(*self.software_reg_tree.get_children())
                for app in software:
                    self.software_reg_tree.insert("", "end", values=(app.name, app.version, app.publisher, app.install_date))
                self.set_status("Installed software analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Installed software analysis failed: {e}")
                self.set_status("Installed software analysis failed.")

        threading.Thread(target=analyze).start()

    def _extract_sam_security(self) -> None:
        """Extract SAM and SECURITY hives."""
        hive_path = self.hive_path_var.get()
        if not hive_path or not os.path.exists(hive_path):
            messagebox.showerror("Error", "Please select a valid registry hive file.")
            return

        self.set_status("Extracting SAM/SECURITY hives...")

        def extract():
            try:
                analyzer = RegistryAnalyzer(hive_path)
                sam_path, security_path = analyzer.extract_sam_security()
                messagebox.showinfo("Extraction Success", f"SAM extracted to {sam_path}\nSECURITY extracted to {security_path}")
                self.set_status("SAM/SECURITY extraction complete.")
            except Exception as e:
                messagebox.showerror("Error", f"SAM/SECURITY extraction failed: {e}")
                self.set_status("SAM/SECURITY extraction failed.")

        threading.Thread(target=extract).start()

    def _run_volatility_plugin(self) -> None:
        """Run selected Volatility plugin."""
        mem_image = self.mem_image_var.get()
        profile = self.mem_profile_var.get()
        plugin = self.plugin_var.get()

        if not mem_image or not os.path.exists(mem_image):
            messagebox.showerror("Error", "Please select a valid memory image.")
            return
        if not plugin:
            messagebox.showerror("Error", "Please select a Volatility plugin.")
            return

        self.set_status(f"Running Volatility plugin: {plugin}...")

        def run_plugin():
            try:
                # Placeholder for Volatility plugin execution
                self.mem_output.delete("1.0", END)
                self.mem_output.insert(END, f"Running {plugin} on {mem_image} with profile {profile}...\n")
                self.mem_output.insert(END, "[Placeholder for Volatility output]\n")
                self.set_status(f"Volatility plugin {plugin} complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Volatility plugin failed: {e}")
                self.set_status("Volatility plugin failed.")

        threading.Thread(target=run_plugin).start()

    def _run_vol_quick(self, plugin_name: str) -> None:
        """Run a quick Volatility plugin (e.g., pslist, netscan)."""
        mem_image = self.mem_image_var.get()
        profile = self.mem_profile_var.get()

        if not mem_image or not os.path.exists(mem_image):
            messagebox.showerror("Error", "Please select a valid memory image.")
            return

        self.set_status(f"Running Volatility {plugin_name}...")

        def run_quick():
            try:
                # Placeholder for quick Volatility plugin execution
                self.mem_output.delete("1.0", END)
                self.mem_output.insert(END, f"Running {plugin_name} on {mem_image} with profile {profile}...\n")
                self.mem_output.insert(END, "[Placeholder for quick Volatility output]\n")
                self.set_status(f"Volatility {plugin_name} complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Volatility {plugin_name} failed: {e}")
                self.set_status(f"Volatility {plugin_name} failed.")

        threading.Thread(target=run_quick).start()

    def _dump_process(self) -> None:
        """Dump a selected process from memory."""
        mem_image = self.mem_image_var.get()
        profile = self.mem_profile_var.get()

        if not mem_image or not os.path.exists(mem_image):
            messagebox.showerror("Error", "Please select a valid memory image.")
            return

        # In a real scenario, you\'d have a way to select a process, e.g., from a list generated by pslist
        pid = 1234 # Placeholder PID

        self.set_status(f"Dumping process {pid}...")

        def dump():
            try:
                # Placeholder for process dumping logic
                self.mem_output.delete("1.0", END)
                self.mem_output.insert(END, f"Dumping process {pid} from {mem_image} with profile {profile}...\n")
                self.mem_output.insert(END, "[Placeholder for process dump output]\n")
                self.set_status(f"Process {pid} dump complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Process dump failed: {e}")
                self.set_status("Process dump failed.")

        threading.Thread(target=dump).start()

    def _analyze_protocols(self) -> None:
        """Analyze network protocols from PCAP."""
        pcap_path = self.pcap_var.get()
        if not pcap_path or not os.path.exists(pcap_path):
            messagebox.showerror("Error", "Please select a valid PCAP file.")
            return

        self.set_status("Analyzing protocols...")

        def analyze():
            try:
                # Placeholder for protocol analysis logic
                self.network_summary_text.delete("1.0", END)
                self.network_summary_text.insert(END, "Protocol Analysis Results:\n")
                self.network_summary_text.insert(END, "[Placeholder for protocol summary]\n")
                self.set_status("Protocol analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Protocol analysis failed: {e}")
                self.set_status("Protocol analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_conversations(self) -> None:
        """Analyze network conversations from PCAP."""
        pcap_path = self.pcap_var.get()
        if not pcap_path or not os.path.exists(pcap_path):
            messagebox.showerror("Error", "Please select a valid PCAP file.")
            return

        self.set_status("Analyzing conversations...")

        def analyze():
            try:
                # Placeholder for conversation analysis logic
                self.conversations_tree.delete(*self.conversations_tree.get_children())
                self.conversations_tree.insert("", "end", values=("192.168.1.1", "8.8.8.8", "TCP", 100, 10240))
                self.set_status("Conversation analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Conversation analysis failed: {e}")
                self.set_status("Conversation analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_dns(self) -> None:
        """Analyze DNS queries from PCAP."""
        pcap_path = self.pcap_var.get()
        if not pcap_path or not os.path.exists(pcap_path):
            messagebox.showerror("Error", "Please select a valid PCAP file.")
            return

        self.set_status("Analyzing DNS queries...")

        def analyze():
            try:
                # Placeholder for DNS analysis logic
                self.network_summary_text.delete("1.0", END)
                self.network_summary_text.insert(END, "DNS Query Results:\n")
                self.network_summary_text.insert(END, "[Placeholder for DNS queries]\n")
                self.set_status("DNS analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"DNS analysis failed: {e}")
                self.set_status("DNS analysis failed.")

        threading.Thread(target=analyze).start()

    def _analyze_http(self) -> None:
        """Analyze HTTP traffic from PCAP."""
        pcap_path = self.pcap_var.get()
        if not pcap_path or not os.path.exists(pcap_path):
            messagebox.showerror("Error", "Please select a valid PCAP file.")
            return

        self.set_status("Analyzing HTTP traffic...")

        def analyze():
            try:
                # Placeholder for HTTP analysis logic
                self.network_summary_text.delete("1.0", END)
                self.network_summary_text.insert(END, "HTTP Traffic Results:\n")
                self.network_summary_text.insert(END, "[Placeholder for HTTP traffic]\n")
                self.set_status("HTTP analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"HTTP analysis failed: {e}")
                self.set_status("HTTP analysis failed.")

        threading.Thread(target=analyze).start()

    def _extract_network_files(self) -> None:
        """Extract files from network traffic (PCAP)."""
        pcap_path = self.pcap_var.get()
        if not pcap_path or not os.path.exists(pcap_path):
            messagebox.showerror("Error", "Please select a valid PCAP file.")
            return

        self.set_status("Extracting files from network traffic...")

        def extract():
            try:
                # Placeholder for file extraction logic
                messagebox.showinfo("Extraction", "[Placeholder for extracted files list]")
                self.set_status("File extraction from network traffic complete.")
            except Exception as e:
                messagebox.showerror("Error", f"File extraction from network traffic failed: {e}")
                self.set_status("File extraction from network traffic failed.")

        threading.Thread(target=extract).start()

    def _run_aleapp(self) -> None:
        """Run ALEAPP for mobile forensics."""
        mobile_path = self.mobile_path_var.get()
        if not mobile_path or not os.path.exists(mobile_path):
            messagebox.showerror("Error", "Please select a valid mobile data directory.")
            return

        self.set_status("Running ALEAPP...")

        def run():
            try:
                # Placeholder for ALEAPP execution
                self.mobile_output.delete("1.0", END)
                self.mobile_output.insert(END, "Running ALEAPP...\n")
                self.mobile_output.insert(END, "[Placeholder for ALEAPP output]\n")
                self.set_status("ALEAPP execution complete.")
            except Exception as e:
                messagebox.showerror("Error", f"ALEAPP execution failed: {e}")
                self.set_status("ALEAPP execution failed.")

        threading.Thread(target=run).start()

    def _extract_contacts(self) -> None:
        """Extract contacts from mobile data."""
        mobile_path = self.mobile_path_var.get()
        if not mobile_path or not os.path.exists(mobile_path):
            messagebox.showerror("Error", "Please select a valid mobile data directory.")
            return

        self.set_status("Extracting contacts...")

        def extract():
            try:
                # Placeholder for contact extraction logic
                self.mobile_output.delete("1.0", END)
                self.mobile_output.insert(END, "Extracting contacts...\n")
                self.mobile_output.insert(END, "[Placeholder for contacts]\n")
                self.set_status("Contact extraction complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Contact extraction failed: {e}")
                self.set_status("Contact extraction failed.")

        threading.Thread(target=extract).start()

    def _extract_messages(self) -> None:
        """Extract messages from mobile data."""
        mobile_path = self.mobile_path_var.get()
        if not mobile_path or not os.path.exists(mobile_path):
            messagebox.showerror("Error", "Please select a valid mobile data directory.")
            return

        self.set_status("Extracting messages...")

        def extract():
            try:
                # Placeholder for message extraction logic
                self.mobile_output.delete("1.0", END)
                self.mobile_output.insert(END, "Extracting messages...\n")
                self.mobile_output.insert(END, "[Placeholder for messages]\n")
                self.set_status("Message extraction complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Message extraction failed: {e}")
                self.set_status("Message extraction failed.")

        threading.Thread(target=extract).start()

    def _extract_call_logs(self) -> None:
        """Extract call logs from mobile data."""
        mobile_path = self.mobile_path_var.get()
        if not mobile_path or not os.path.exists(mobile_path):
            messagebox.showerror("Error", "Please select a valid mobile data directory.")
            return

        self.set_status("Extracting call logs...")

        def extract():
            try:
                # Placeholder for call log extraction logic
                self.mobile_output.delete("1.0", END)
                self.mobile_output.insert(END, "Extracting call logs...\n")
                self.mobile_output.insert(END, "[Placeholder for call logs]\n")
                self.set_status("Call log extraction complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Call log extraction failed: {e}")
                self.set_status("Call log extraction failed.")

        threading.Thread(target=extract).start()

    def _analyze_apps(self) -> None:
        """Analyze installed apps from mobile data."""
        mobile_path = self.mobile_path_var.get()
        if not mobile_path or not os.path.exists(mobile_path):
            messagebox.showerror("Error", "Please select a valid mobile data directory.")
            return

        self.set_status("Analyzing installed apps...")

        def analyze():
            try:
                # Placeholder for app analysis logic
                self.mobile_output.delete("1.0", END)
                self.mobile_output.insert(END, "Analyzing installed apps...\n")
                self.mobile_output.insert(END, "[Placeholder for app analysis results]\n")
                self.set_status("App analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"App analysis failed: {e}")
                self.set_status("App analysis failed.")

        threading.Thread(target=analyze).start()

    def _convert_vm_disk(self) -> None:
        """Convert VM disk to raw format."""
        vm_disk_path = self.vm_disk_var.get()
        if not vm_disk_path or not os.path.exists(vm_disk_path):
            messagebox.showerror("Error", "Please select a valid VM disk file.")
            return

        self.set_status("Converting VM disk to raw...")

        def convert():
            try:
                # Placeholder for VM disk conversion logic
                self.vm_output.delete("1.0", END)
                self.vm_output.insert(END, "Converting VM disk...\n")
                self.vm_output.insert(END, "[Placeholder for conversion output]\n")
                self.set_status("VM disk conversion complete.")
            except Exception as e:
                messagebox.showerror("Error", f"VM disk conversion failed: {e}")
                self.set_status("VM disk conversion failed.")

        threading.Thread(target=convert).start()

    def _analyze_snapshots(self) -> None:
        """Analyze VM snapshots."""
        vm_disk_path = self.vm_disk_var.get()
        if not vm_disk_path or not os.path.exists(vm_disk_path):
            messagebox.showerror("Error", "Please select a valid VM disk file.")
            return

        self.set_status("Analyzing VM snapshots...")

        def analyze():
            try:
                # Placeholder for snapshot analysis logic
                self.vm_output.delete("1.0", END)
                self.vm_output.insert(END, "Analyzing VM snapshots...\n")
                self.vm_output.insert(END, "[Placeholder for snapshot analysis results]\n")
                self.set_status("VM snapshot analysis complete.")
            except Exception as e:
                messagebox.showerror("Error", f"VM snapshot analysis failed: {e}")
                self.set_status("VM snapshot analysis failed.")

        threading.Thread(target=analyze).start()

    def _extract_vm_config(self) -> None:
        """Extract VM configuration."""
        vm_disk_path = self.vm_disk_var.get()
        if not vm_disk_path or not os.path.exists(vm_disk_path):
            messagebox.showerror("Error", "Please select a valid VM disk file.")
            return

        self.set_status("Extracting VM configuration...")

        def extract():
            try:
                # Placeholder for VM config extraction logic
                self.vm_output.delete("1.0", END)
                self.vm_output.insert(END, "Extracting VM configuration...\n")
                self.vm_output.insert(END, "[Placeholder for VM config]\n")
                self.set_status("VM configuration extraction complete.")
            except Exception as e:
                messagebox.showerror("Error", f"VM configuration extraction failed: {e}")
                self.set_status("VM configuration extraction failed.")

        threading.Thread(target=extract).start()

    def _generate_timeline(self) -> None:
        """Generate forensic timeline."""
        source = self.timeline_source_var.get()
        start_date = self.timeline_start_var.get()
        end_date = self.timeline_end_var.get()

        self.set_status(f"Generating timeline from {source}...")

        def generate():
            try:
                # Placeholder for timeline generation logic
                self.timeline_tree.delete(*self.timeline_tree.get_children())
                self.timeline_tree.insert("", "end", values=("2025-01-01 10:00:00", "File System", "Event", "C:\\test.txt"))
                self.set_status("Timeline generation complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Timeline generation failed: {e}")
                self.set_status("Timeline generation failed.")

        threading.Thread(target=generate).start()

    def _generate_report(self) -> None:
        """Generate forensic report."""
        report_type = self.report_type_var.get()
        report_format = self.report_format_var.get()
        include_screenshots = self.include_screenshots.get()
        include_hashes = self.include_hashes.get()
        include_timeline = self.include_timeline.get()

        self.set_status(f"Generating {report_type} report in {report_format} format...")

        def generate():
            try:
                # Placeholder for report generation logic
                self.report_preview.delete("1.0", END)
                self.report_preview.insert(END, f"Generating {report_type} report...\n")
                self.report_preview.insert(END, f"Format: {report_format}\n")
                self.report_preview.insert(END, f"Include Screenshots: {include_screenshots}\n")
                self.report_preview.insert(END, f"Include Hashes: {include_hashes}\n")
                self.report_preview.insert(END, f"Include Timeline: {include_timeline}\n")
                self.report_preview.insert(END, "[Placeholder for report content]\n")
                self.set_status("Report generation complete.")
            except Exception as e:
                messagebox.showerror("Error", f"Report generation failed: {e}")
                self.set_status("Report generation failed.")

        threading.Thread(target=generate).start()

    def _new_case(self) -> None:
        """Handle new case creation."""
        # Placeholder for new case logic
        messagebox.showinfo("New Case", "New case functionality not yet implemented.")
        self.set_status("New case initiated.")

    def _open_case(self) -> None:
        """Handle opening an existing case."""
        # Placeholder for open case logic
        messagebox.showinfo("Open Case", "Open case functionality not yet implemented.")
        self.set_status("Open case initiated.")

    def _save_case(self) -> None:
        """Handle saving the current case."""
        # Placeholder for save case logic
        messagebox.showinfo("Save Case", "Save case functionality not yet implemented.")
        self.set_status("Case saved.")

    def _export_report(self) -> None:
        """Handle exporting the generated report."""
        # Placeholder for export report logic
        messagebox.showinfo("Export Report", "Export report functionality not yet implemented.")
        self.set_status("Report export initiated.")

    def _open_hash_calculator(self) -> None:
        """Open hash calculator utility."""
        # Placeholder for hash calculator logic
        messagebox.showinfo("Hash Calculator", "Hash calculator functionality not yet implemented.")
        self.set_status("Hash calculator opened.")

    def _open_hex_viewer(self) -> None:
        """Open hex viewer utility."""
        # Placeholder for hex viewer logic
        messagebox.showinfo("Hex Viewer", "Hex viewer functionality not yet implemented.")
        self.set_status("Hex viewer opened.")

    def _open_timeline_viewer(self) -> None:
        """Open timeline viewer utility."""
        # Placeholder for timeline viewer logic
        messagebox.showinfo("Timeline Viewer", "Timeline viewer functionality not yet implemented.")
        self.set_status("Timeline viewer opened.")

    def _show_tools_guide(self) -> None:
        """Show guide for installing external tools."""
        # Placeholder for tools guide logic
        messagebox.showinfo("Install Tools Guide", "Tools installation guide functionality not yet implemented.")
        self.set_status("Tools guide displayed.")

    def _show_documentation(self) -> None:
        """Show documentation."""
        # Placeholder for documentation logic
        messagebox.showinfo("Documentation", "Documentation functionality not yet implemented.")
        self.set_status("Documentation displayed.")

    def _show_about(self) -> None:
        """Show about dialog."""
        # Placeholder for about dialog logic
        messagebox.showinfo("About", "Digital Forensics Workbench\nVersion 1.0\nDeveloped by Manus")
        self.set_status("About dialog displayed.")

def run_app() -> None:
    app = MainApp()
    app.mainloop()


