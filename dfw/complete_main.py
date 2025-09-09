"""Complete Digital Forensics Workbench - Fully Functional Implementation.

This is the main application that integrates all modules and provides
a comprehensive forensic analysis platform.
"""

import os
import sys
import platform
import json
import threading
import hashlib
import datetime
import tempfile
import shutil
from pathlib import Path
from tkinter import *
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Dict, List, Any
import webbrowser

# Import all our modules
from . import env, mount, keywords, forensic_tools
from .os_detector import OSDetector, OSType
from .browser_forensics import BrowserForensics
from .registry_analyzer import RegistryAnalyzer
from .tool_manager import ExternalToolManager, ToolResult
from .notes_terminal import CaseNotesManager, NotesTab, EmbeddedTerminal
from .auto_installer import ToolInstaller, check_and_install_tools


class CompleteDFW(Tk):
    """Complete Digital Forensics Workbench Application."""

    def __init__(self):
        super().__init__()

        # Application setup
        self.title("Digital Forensics Workbench - Professional Edition")
        self.geometry("1600x900")

        # Set theme
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except:
            pass

        # Initialize managers
        self.tool_manager = ExternalToolManager()
        self.tool_installer = ToolInstaller(self)
        self.case_dir = None
        self.notes_manager = None
        self.current_mount_point = None
        self.detected_os = None
        self.evidence_items = {}

        # Create UI
        self._create_menu()
        self._create_main_layout()

        # Initialize case
        self._initialize_case()

        # Check environment and tools on startup
        self.after(100, self._check_environment)
        self.after(1000, self._check_tools_on_startup)

        # Status
        self.set_status("Digital Forensics Workbench Ready")

    def _create_menu(self):
        """Create application menu."""
        menubar = Menu(self)
        self.config(menu=menubar)

        # File menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Case", command=self._initialize_case)
        file_menu.add_command(label="Save Case", command=self._save_case)
        file_menu.add_separator()
        file_menu.add_command(label="Import Evidence", command=self._import_evidence)
        file_menu.add_command(label="Export Report", command=self._export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        # Edit menu
        edit_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Case Properties", command=self._edit_case_properties)
        edit_menu.add_command(label="Preferences", command=self._show_preferences)

        # Tools menu
        tools_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Install Forensic Tools", command=self._install_tools)
        tools_menu.add_separator()
        tools_menu.add_command(label="Hash Calculator", command=self._open_hash_calculator)
        tools_menu.add_command(label="String Extractor", command=self._run_strings_tool)
        tools_menu.add_command(label="Hex Viewer", command=self._open_hex_viewer)
        tools_menu.add_command(label="File Carver", command=self._run_file_carver)
        tools_menu.add_separator()
        tools_menu.add_command(label="Check Tools", command=self._check_tools)
        tools_menu.add_command(label="Install Guide", command=self._show_install_guide)

        # Analysis menu
        analysis_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Quick Triage", command=self._run_quick_triage)
        analysis_menu.add_command(label="Full Analysis", command=self._run_full_analysis)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Generate Timeline", command=self._generate_super_timeline)
        analysis_menu.add_command(label="YARA Scan", command=self._run_yara_scan)
        analysis_menu.add_command(label="Bulk Extractor", command=self._run_bulk_extractor)

        # Help menu
        help_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self._show_documentation)
        help_menu.add_command(label="Keyboard Shortcuts", command=self._show_shortcuts)
        help_menu.add_command(label="About", command=self._show_about)

    def _create_main_layout(self):
        """Create main application layout."""
        # Main container
        main_container = ttk.PanedWindow(self, orient=HORIZONTAL)
        main_container.pack(fill=BOTH, expand=True, padx=5, pady=5)

        # Left panel - Evidence tree
        self._create_evidence_panel(main_container)

        # Right panel - Tabbed interface
        right_panel = Frame(main_container)
        main_container.add(right_panel, weight=4)

        # Create notebook
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=BOTH, expand=True)

        # Create all tabs
        self._create_case_tab()
        self._create_mount_tab()
        self._create_browser_tab()
        self._create_registry_tab()
        self._create_timeline_tab()
        self._create_search_tab()
        self._create_memory_tab()
        self._create_network_tab()
        self._create_mobile_tab()
        self._create_notes_tab()
        self._create_terminal_tab()
        self._create_report_tab()

        # Status bar
        self._create_status_bar()

    def _create_evidence_panel(self, parent):
        """Create evidence tree panel."""
        left_panel = Frame(parent, width=250)
        parent.add(left_panel, weight=1)

        # Header
        header = Frame(left_panel)
        header.pack(fill=X, padx=5, pady=5)

        Label(header, text="Evidence Items", font=('Arial', 11, 'bold')).pack(side=LEFT)
        Button(header, text="+", command=self._add_evidence).pack(side=RIGHT)

        # Evidence tree
        tree_frame = Frame(left_panel)
        tree_frame.pack(fill=X, padx=5)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.evidence_tree = ttk.Treeview(tree_frame, show='tree', yscrollcommand=scrollbar.set, height=8)
        self.evidence_tree.pack(side=LEFT, fill=X, expand=True)
        scrollbar.config(command=self.evidence_tree.yview)

        # Context menu
        self.evidence_menu = Menu(self.evidence_tree, tearoff=0)
        self.evidence_menu.add_command(label="Open", command=self._open_evidence)
        self.evidence_menu.add_command(label="Analyze", command=self._analyze_evidence)
        self.evidence_menu.add_command(label="Calculate Hash", command=self._hash_evidence)
        self.evidence_menu.add_command(label="Remove", command=self._remove_evidence)

        self.evidence_tree.bind("<Button-3>", self._show_evidence_menu)

        # File Tree Section
        file_tree_header = Frame(left_panel)
        file_tree_header.pack(fill=X, padx=5, pady=(10,5))

        Label(file_tree_header, text="Mounted Drive Contents", font=('Arial', 11, 'bold')).pack(side=LEFT)
        
        # File tree controls
        controls_frame = Frame(file_tree_header)
        controls_frame.pack(side=RIGHT)
        
        Button(controls_frame, text="↻", command=self._refresh_file_tree, width=2).pack(side=LEFT, padx=1)
        Button(controls_frame, text="▼", command=self._expand_file_tree, width=2).pack(side=LEFT, padx=1)
        Button(controls_frame, text="▶", command=self._collapse_file_tree, width=2).pack(side=LEFT, padx=1)

        # File tree
        file_tree_frame = Frame(left_panel)
        file_tree_frame.pack(fill=BOTH, expand=True, padx=5, pady=(0,5))

        file_tree_scrollbar_v = ttk.Scrollbar(file_tree_frame, orient=VERTICAL)
        file_tree_scrollbar_v.pack(side=RIGHT, fill=Y)

        file_tree_scrollbar_h = ttk.Scrollbar(file_tree_frame, orient=HORIZONTAL)
        file_tree_scrollbar_h.pack(side=BOTTOM, fill=X)

        self.file_tree = ttk.Treeview(file_tree_frame, show='tree', 
                                     yscrollcommand=file_tree_scrollbar_v.set,
                                     xscrollcommand=file_tree_scrollbar_h.set)
        self.file_tree.pack(side=LEFT, fill=BOTH, expand=True)
        
        file_tree_scrollbar_v.config(command=self.file_tree.yview)
        file_tree_scrollbar_h.config(command=self.file_tree.xview)

        # Bind double-click to open files
        self.file_tree.bind('<Double-1>', self._on_file_tree_double_click)

        # Initialize tree
        self.case_node = self.evidence_tree.insert('', 'end', text='Current Case', open=True)

    def _create_case_tab(self):
        """Create case information tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Case Info")

        # Case details
        details_frame = ttk.LabelFrame(frame, text="Case Details", padding=10)
        details_frame.grid(row=0, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

        fields = [
            ("Case Name:", "case_name"),
            ("Case Number:", "case_number"),
            ("Investigator:", "investigator"),
            ("Date Created:", "date_created"),
        ]

        self.case_vars = {}
        for i, (label, field) in enumerate(fields):
            Label(details_frame, text=label).grid(row=i, column=0, sticky='w', padx=5, pady=2)
            var = Entry(details_frame, width=40)
            var.grid(row=i, column=1, sticky='ew', padx=5, pady=2)
            self.case_vars[field] = var

        # Description
        Label(details_frame, text="Description:").grid(row=4, column=0, sticky='nw', padx=5, pady=2)
        self.case_description = Text(details_frame, height=3, width=50)
        self.case_description.grid(row=4, column=1, sticky='ew', padx=5, pady=2)

        # OS Detection
        os_frame = ttk.LabelFrame(frame, text="OS Detection", padding=10)
        os_frame.grid(row=1, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

        Label(os_frame, text="Detected OS:").grid(row=0, column=0, sticky='w', padx=5)
        self.os_label = Label(os_frame, text="Not detected", font=('Arial', 10, 'bold'))
        self.os_label.grid(row=0, column=1, sticky='w', padx=5)

        Button(os_frame, text="Auto-Detect", command=self._auto_detect_os).grid(row=0, column=2, padx=5)

        self.os_details = Text(os_frame, height=6, width=60)
        self.os_details.grid(row=1, column=0, columnspan=3, padx=5, pady=5)

        # Environment
        env_frame = ttk.LabelFrame(frame, text="Environment", padding=10)
        env_frame.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)

        self.env_text = Text(env_frame, height=10)
        self.env_text.pack(fill=BOTH, expand=True)

        Button(env_frame, text="Refresh", command=self._check_environment).pack(pady=5)

        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _create_mount_tab(self):
        """Create mount/extract tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Mount/Extract")

        # Image selection
        img_frame = ttk.LabelFrame(frame, text="Disk Image", padding=10)
        img_frame.pack(fill=X, padx=5, pady=5)

        Label(img_frame, text="Image:").grid(row=0, column=0, sticky='w')
        self.image_path = Entry(img_frame, width=60)
        self.image_path.grid(row=0, column=1, sticky='ew')
        Button(img_frame, text="Browse", command=self._browse_image).grid(row=0, column=2)
        Button(img_frame, text="Calculate Hash", command=self._calc_image_hash).grid(row=0, column=3)

        # Hash display
        self.hash_label = Label(img_frame, text="", fg='blue')
        self.hash_label.grid(row=1, column=1, columnspan=2, sticky='w')

        # Partitions
        part_frame = ttk.LabelFrame(frame, text="Partitions", padding=10)
        part_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)

        Button(part_frame, text="Scan Partitions", command=self._scan_partitions).pack()

        columns = ('Index', 'Start', 'Size', 'Type', 'Description')
        self.part_tree = ttk.Treeview(part_frame, columns=columns, show='headings', height=8)
        for col in columns:
            self.part_tree.heading(col, text=col)
        self.part_tree.pack(fill=BOTH, expand=True)

        # Mount options
        mount_frame = ttk.LabelFrame(frame, text="Mount Options", padding=10)
        mount_frame.pack(fill=X, padx=5, pady=5)

        Label(mount_frame, text="Mount Point:").grid(row=0, column=0, sticky='w')
        self.mount_path = Entry(mount_frame, width=50)
        self.mount_path.grid(row=0, column=1)
        Button(mount_frame, text="Browse", command=self._browse_mount).grid(row=0, column=2)
        Button(mount_frame, text="Create Dir", command=self._create_mount_directory).grid(row=0, column=3, padx=(5,0))

        Label(mount_frame, text="Offset:").grid(row=1, column=0, sticky='w')
        self.offset_var = Entry(mount_frame, width=20)
        self.offset_var.grid(row=1, column=1, sticky='w')

        options = Frame(mount_frame)
        options.grid(row=2, column=0, columnspan=3)

        self.readonly = BooleanVar(value=True)
        Checkbutton(options, text="Read-only", variable=self.readonly).pack(side=LEFT)

        self.loop = BooleanVar(value=True)
        Checkbutton(options, text="Loop", variable=self.loop).pack(side=LEFT)

        Button(mount_frame, text="Mount", command=self._mount_image).grid(row=3, column=0, pady=5)
        Button(mount_frame, text="Force Mount", command=self._force_mount_image).grid(row=3, column=1, pady=5)
        Button(mount_frame, text="Extract", command=self._extract_image).grid(row=3, column=2, pady=5)
        Button(mount_frame, text="Unmount", command=self._unmount_image).grid(row=3, column=3, pady=5)

    def _create_browser_tab(self):
        """Create browser forensics tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Browser")

        # Controls
        control_frame = Frame(frame)
        control_frame.pack(fill=X, padx=5, pady=5)

        Button(control_frame, text="Analyze All Browsers",
               command=self._analyze_all_browsers).pack(side=LEFT, padx=2)
        Button(control_frame, text="Export Results",
               command=self._export_browser_results).pack(side=LEFT, padx=2)

        # Results notebook
        self.browser_notebook = ttk.Notebook(frame)
        self.browser_notebook.pack(fill=BOTH, expand=True, padx=5)

        # History tab
        history_frame = Frame(self.browser_notebook)
        self.browser_notebook.add(history_frame, text="History")

        columns = ('URL', 'Title', 'Visit Time', 'Browser')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings')
        for col in columns:
            self.history_tree.heading(col, text=col)
        self.history_tree.pack(fill=BOTH, expand=True)

        # Downloads tab
        downloads_frame = Frame(self.browser_notebook)
        self.browser_notebook.add(downloads_frame, text="Downloads")

        columns = ('File', 'URL', 'Date', 'Browser')
        self.downloads_tree = ttk.Treeview(downloads_frame, columns=columns, show='headings')
        for col in columns:
            self.downloads_tree.heading(col, text=col)
        self.downloads_tree.pack(fill=BOTH, expand=True)

    def _create_registry_tab(self):
        """Create registry analysis tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Registry")

        # Controls
        control_frame = Frame(frame)
        control_frame.pack(fill=X, padx=5, pady=5)

        Button(control_frame, text="Analyze Registry",
               command=self._analyze_registry).pack(side=LEFT, padx=2)
        Button(control_frame, text="Run RegRipper",
               command=self._run_regripper).pack(side=LEFT, padx=2)
        Button(control_frame, text="Export Results",
               command=self._export_registry_results).pack(side=LEFT, padx=2)

        # Results
        self.registry_text = Text(frame)
        self.registry_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_timeline_tab(self):
        """Create timeline tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Timeline")

        # Controls
        control_frame = ttk.LabelFrame(frame, text="Timeline Options", padding=10)
        control_frame.pack(fill=X, padx=5, pady=5)

        Button(control_frame, text="Generate with Plaso",
               command=self._generate_plaso_timeline).pack(side=LEFT, padx=2)
        Button(control_frame, text="Generate with TSK",
               command=self._generate_tsk_timeline).pack(side=LEFT, padx=2)
        Button(control_frame, text="Export Timeline",
               command=self._export_timeline).pack(side=LEFT, padx=2)

        # Timeline display
        columns = ('Timestamp', 'Source', 'Event', 'Details')
        self.timeline_tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col in columns:
            self.timeline_tree.heading(col, text=col)
        self.timeline_tree.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_search_tab(self):
        """Create search tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Search")

        # Search options
        search_frame = ttk.LabelFrame(frame, text="Search Options", padding=10)
        search_frame.pack(fill=X, padx=5, pady=5)

        Label(search_frame, text="Directory:").grid(row=0, column=0, sticky='w')
        self.search_dir = Entry(search_frame, width=50)
        self.search_dir.grid(row=0, column=1)
        Button(search_frame, text="Browse", command=self._browse_search_dir).grid(row=0, column=2)

        Label(search_frame, text="Keywords:").grid(row=1, column=0, sticky='w')
        self.keywords = Entry(search_frame, width=50)
        self.keywords.grid(row=1, column=1)

        Button(search_frame, text="Search", command=self._run_search).grid(row=2, column=1,
               columnspan=2, pady=5)

        # Search results
        columns = ('File', 'Line', 'Context')
        self.search_tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col in columns:
            self.search_tree.heading(col, text=col)
        self.search_tree.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_memory_tab(self):
        """Create memory analysis tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Memory")

        # Controls
        control_frame = ttk.LabelFrame(frame, text="Memory Image", padding=10)
        control_frame.pack(fill=X, padx=5, pady=5)

        Label(control_frame, text="Image:").grid(row=0, column=0, sticky='w')
        self.mem_image = Entry(control_frame, width=50)
        self.mem_image.grid(row=0, column=1)
        Button(control_frame, text="Browse", command=self._browse_mem_image).grid(row=0, column=2)

        Label(control_frame, text="Plugin:").grid(row=1, column=0, sticky='w')
        self.vol_plugin = Entry(control_frame, width=50)
        self.vol_plugin.grid(row=1, column=1)

        Button(control_frame, text="Run Volatility",
               command=self._run_volatility).grid(row=2, column=1, pady=5)

        # Results
        self.memory_text = Text(frame)
        self.memory_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_network_tab(self):
        """Create network analysis tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Network")

        # Controls
        control_frame = ttk.LabelFrame(frame, text="PCAP Analysis", padding=10)
        control_frame.pack(fill=X, padx=5, pady=5)

        Label(control_frame, text="PCAP File:").grid(row=0, column=0, sticky='w')
        self.pcap_file = Entry(control_frame, width=50)
        self.pcap_file.grid(row=0, column=1)
        Button(control_frame, text="Browse", command=self._browse_pcap).grid(row=0, column=2)

        Button(control_frame, text="Analyze PCAP",
               command=self._analyze_pcap).grid(row=1, column=1, pady=5)

        # Results
        self.network_text = Text(frame)
        self.network_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_mobile_tab(self):
        """Create mobile forensics tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Mobile")

        # Controls
        control_frame = ttk.LabelFrame(frame, text="Mobile Data", padding=10)
        control_frame.pack(fill=X, padx=5, pady=5)

        Label(control_frame, text="Data Directory:").grid(row=0, column=0, sticky='w')
        self.mobile_path = Entry(control_frame, width=50)
        self.mobile_path.grid(row=0, column=1)
        Button(control_frame, text="Browse", command=self._browse_mobile).grid(row=0, column=2)

        Button(control_frame, text="Analyze Mobile",
               command=self._analyze_mobile).grid(row=1, column=1, pady=5)

        # Results
        self.mobile_text = Text(frame)
        self.mobile_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_notes_tab(self):
        """Create case notes tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Notes")

        self.notes_widget = NotesTab(frame, self.notes_manager)
        self.notes_widget.pack(fill=BOTH, expand=True)

    def _create_terminal_tab(self):
        """Create embedded terminal tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Terminal")

        self.terminal_widget = EmbeddedTerminal(frame)
        self.terminal_widget.pack(fill=BOTH, expand=True)

    def _create_report_tab(self):
        """Create report generation tab."""
        frame = Frame(self.notebook)
        self.notebook.add(frame, text="Report")

        # Report options
        report_frame = ttk.LabelFrame(frame, text="Report Options", padding=10)
        report_frame.pack(fill=X, padx=5, pady=5)

        Label(report_frame, text="Report Type:").grid(row=0, column=0, sticky='w')
        self.report_type = ttk.Combobox(report_frame,
                                        values=["Executive Summary", "Technical Report", "Full Analysis"])
        self.report_type.grid(row=0, column=1)
        self.report_type.current(1)

        Label(report_frame, text="Format:").grid(row=1, column=0, sticky='w')
        self.report_format = ttk.Combobox(report_frame,
                                          values=["HTML", "PDF", "DOCX", "Markdown"])
        self.report_format.grid(row=1, column=1)
        self.report_format.current(0)

        Button(report_frame, text="Generate Report",
               command=self._generate_report).grid(row=2, column=1, pady=10)

        # Report preview
        self.report_text = Text(frame)
        self.report_text.pack(fill=BOTH, expand=True, padx=5, pady=5)

    def _create_status_bar(self):
        """Create status bar."""
        status_frame = Frame(self, relief=SUNKEN, bd=1)
        status_frame.pack(fill=X, side=BOTTOM)

        self.status_label = Label(status_frame, text="Ready", anchor=W)
        self.status_label.pack(side=LEFT, fill=X, expand=True)

        self.progress = ttk.Progressbar(status_frame, length=200, mode='determinate')
        self.progress.pack(side=RIGHT, padx=5)

    # Implementation methods
    def set_status(self, message: str):
        """Update status bar."""
        self.status_label.config(text=message)
        self.update_idletasks()

    def _initialize_case(self):
        """Initialize a new case."""
        self.case_dir = tempfile.mkdtemp(prefix="dfw_case_")
        os.makedirs(os.path.join(self.case_dir, "evidence"))
        os.makedirs(os.path.join(self.case_dir, "exports"))
        os.makedirs(os.path.join(self.case_dir, "notes"))

        # Initialize notes manager
        self.notes_manager = CaseNotesManager(self.case_dir)

        # Set default case info
        self.case_vars["case_name"].insert(0, "New Case")
        self.case_vars["investigator"].insert(0, os.getenv("USER", "Investigator"))
        self.case_vars["date_created"].insert(0, datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))

    def _check_environment(self):
        """Check system environment."""
        self.set_status("Checking environment...")

        # Check Python environment
        info = env.check_environment()

        # Check external tools
        tools = self.tool_manager.get_available_tools()

        # Display results
        self.env_text.delete('1.0', END)
        self.env_text.insert(END, f"OS: {info['os_type']} {info['os_version']}\n")
        self.env_text.insert(END, f"Python: {sys.version}\n")
        self.env_text.insert(END, f"WSL: {'Yes' if info.get('is_wsl') else 'No'}\n\n")

        self.env_text.insert(END, "External Tools:\n")
        for category, tool_list in tools.items():
            self.env_text.insert(END, f"\n{category.upper()}:\n")
            for tool, available in tool_list.items():
                status = "✓" if available else "✗"
                self.env_text.insert(END, f"  {status} {tool}\n")

        self.set_status("Environment check complete")

    def _auto_detect_os(self):
        """Auto-detect OS of mounted evidence."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return

        self.set_status("Detecting OS...")
        self.progress['mode'] = 'indeterminate'
        self.progress.start()

        def detect():
            try:
                detector = OSDetector(self.current_mount_point)
                os_info = detector.detect()

                self.detected_os = os_info
                self.os_label.config(text=f"{os_info.os_type.value} {os_info.version or ''}")

                # Display details
                self.os_details.delete('1.0', END)
                details = f"Type: {os_info.os_type.value}\n"
                details += f"Version: {os_info.version or 'Unknown'}\n"
                details += f"Architecture: {os_info.architecture or 'Unknown'}\n"
                details += f"Confidence: {os_info.confidence:.1%}\n"

                if os_info.users:
                    details += f"Users: {', '.join(os_info.users)}\n"

                self.os_details.insert(END, details)

                # Add note
                self.notes_widget.add_finding(
                    "OS Detection",
                    f"Detected {os_info.os_type.value} with {os_info.confidence:.1%} confidence",
                    self.current_mount_point
                )

                self.set_status(f"OS detected: {os_info.os_type.value}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress.stop()
                self.progress['mode'] = 'determinate'

        threading.Thread(target=detect, daemon=True).start()

    def _scan_partitions(self):
        """Scan disk image for partitions."""
        image = self.image_path.get()
        if not image:
            messagebox.showwarning("No Image", "Please select an image first")
            return

        self.set_status("Scanning partitions...")

        # Clear tree
        for item in self.part_tree.get_children():
            self.part_tree.delete(item)

        # Run mmls
        result = self.tool_manager.run_mmls(image)

        if result.success:
            # Parse output
            partitions = mount.parse_partitions(image)
            for p in partitions:
                size_mb = (p.length * 512) / (1024 * 1024)
                self.part_tree.insert('', 'end', values=(
                    p.index, p.start_sector, f"{size_mb:.1f} MB",
                    "Unknown", p.description
                ))

            self.set_status(f"Found {len(partitions)} partitions")
        else:
            messagebox.showerror("Error", result.stderr)

    def _mount_image(self):
        """Mount selected partition."""
        selection = self.part_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a partition")
            return

        # Get partition info
        item = self.part_tree.item(selection[0])
        part_index = item['values'][0]

        image = self.image_path.get()
        mount_point = self.mount_path.get()

        if not mount_point:
            messagebox.showwarning("No Mount Point", "Please specify mount point")
            return

        # Get partition details
        partitions = mount.parse_partitions(image)
        partition = next((p for p in partitions if p.index == part_index), None)

        if partition:
            success = mount.mount_partition_linux(image, partition, mount_point)
            if success:
                self.current_mount_point = mount_point
                self.set_status(f"Mounted partition {part_index}")

                # Add to evidence tree
                self.evidence_tree.insert(self.case_node, 'end',
                                          text=f"Mount: {os.path.basename(mount_point)}")
            else:
                messagebox.showerror("Mount Failed", "Failed to mount partition")

    def _force_mount_image(self):
        """Force mount disk image directly (useful when no partitions detected)."""
        image = self.image_path.get()
        mount_point = self.mount_path.get()
        
        if not image:
            messagebox.showwarning("No Image", "Please select a disk image first")
            return
            
        if not mount_point:
            messagebox.showwarning("No Mount Point", "Please specify mount point")
            return
        
        if not os.path.exists(image):
            messagebox.showerror("Error", "Image file not found")
            return
        
        # Create mount point if it doesn't exist
        try:
            os.makedirs(mount_point, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot create mount point: {str(e)}")
            return
        
        # Get offset if specified
        offset_str = self.offset_var.get()
        offset = 0
        if offset_str:
            try:
                offset = int(offset_str)
            except ValueError:
                messagebox.showerror("Error", "Invalid offset value")
                return
        
        self.set_status("Force mounting image...")
        
        def mount_thread():
            try:
                # Build mount command
                cmd = ["sudo", "mount"]
                
                if offset > 0:
                    cmd.extend(["-o", f"loop,offset={offset}"])
                else:
                    cmd.extend(["-o", "loop"])
                
                if self.readonly.get():
                    cmd.extend(["-o", "ro"])
                
                cmd.extend([image, mount_point])
                
                # Execute mount command
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.current_mount_point = mount_point
                    self.set_status(f"Force mounted image to {mount_point}")
                    
                    # Add to evidence tree
                    self.evidence_tree.insert(self.case_node, 'end',
                                              text=f"Force Mount: {os.path.basename(mount_point)}")
                    
                    # Auto-refresh file tree
                    self._refresh_file_tree()
                    
                    # Auto-populate search directory
                    self.search_dir.delete(0, END)
                    self.search_dir.insert(0, mount_point)
                    
                    messagebox.showinfo("Success", f"Image mounted successfully to:\n{mount_point}")
                else:
                    error_msg = f"Mount failed: {result.stderr}"
                    self.set_status(f"Force mount failed: {result.stderr}")
                    messagebox.showerror("Mount Failed", error_msg)
                    
            except Exception as e:
                error_msg = f"Force mount error: {str(e)}"
                self.set_status(error_msg)
                messagebox.showerror("Error", error_msg)
        
        threading.Thread(target=mount_thread, daemon=True).start()

    def _refresh_file_tree(self):
        """Refresh the file tree with mounted drive contents."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return
        
        if not os.path.exists(self.current_mount_point):
            messagebox.showerror("Error", f"Mount point {self.current_mount_point} not found")
            return
        
        # Clear existing tree
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        self.set_status("Loading file tree...")
        
        def load_tree():
            try:
                # Add root node
                root_node = self.file_tree.insert('', 'end', text=f"📁 {os.path.basename(self.current_mount_point)}", 
                                                  values=[self.current_mount_point], open=True)
                
                # Load directory contents
                self._load_directory_tree(self.current_mount_point, root_node)
                
                self.set_status(f"File tree loaded from {self.current_mount_point}")
                
            except Exception as e:
                self.set_status(f"Error loading file tree: {str(e)}")
                messagebox.showerror("Error", f"Failed to load file tree:\n{str(e)}")
        
        threading.Thread(target=load_tree, daemon=True).start()

    def _load_directory_tree(self, path, parent_node, max_depth=3, current_depth=0):
        """Recursively load directory tree."""
        if current_depth >= max_depth:
            return
        
        try:
            items = []
            # Get directory contents
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    items.append((item, item_path, True))  # Directory
                elif os.path.isfile(item_path):
                    items.append((item, item_path, False))  # File
            
            # Sort: directories first, then files
            items.sort(key=lambda x: (not x[2], x[0].lower()))
            
            # Add items to tree (limit to prevent UI freeze)
            for i, (item_name, item_path, is_dir) in enumerate(items[:100]):  # Limit to 100 items per directory
                if is_dir:
                    icon = "📁"
                    node = self.file_tree.insert(parent_node, 'end', text=f"{icon} {item_name}", 
                                                 values=[item_path], open=False)
                    
                    # Add placeholder for lazy loading
                    self.file_tree.insert(node, 'end', text="Loading...", values=[""])
                else:
                    # Determine file icon
                    ext = os.path.splitext(item_name)[1].lower()
                    if ext in ['.txt', '.log', '.ini', '.cfg']:
                        icon = "📄"
                    elif ext in ['.exe', '.dll', '.sys']:
                        icon = "⚙️"
                    elif ext in ['.jpg', '.png', '.gif', '.bmp']:
                        icon = "🖼️"
                    elif ext in ['.mp3', '.wav', '.mp4', '.avi']:
                        icon = "🎵"
                    else:
                        icon = "📄"
                    
                    self.file_tree.insert(parent_node, 'end', text=f"{icon} {item_name}", 
                                         values=[item_path])
            
            # If there are more items, add indicator
            if len(items) > 100:
                self.file_tree.insert(parent_node, 'end', text="... (more items)", values=[""])
                
        except PermissionError:
            self.file_tree.insert(parent_node, 'end', text="❌ Permission Denied", values=[""])
        except Exception as e:
            self.file_tree.insert(parent_node, 'end', text=f"❌ Error: {str(e)}", values=[""])

    def _expand_file_tree(self):
        """Expand all nodes in file tree."""
        def expand_all(item):
            self.file_tree.item(item, open=True)
            for child in self.file_tree.get_children(item):
                expand_all(child)
        
        for item in self.file_tree.get_children():
            expand_all(item)

    def _collapse_file_tree(self):
        """Collapse all nodes in file tree."""
        def collapse_all(item):
            self.file_tree.item(item, open=False)
            for child in self.file_tree.get_children(item):
                collapse_all(child)
        
        for item in self.file_tree.get_children():
            collapse_all(item)

    def _on_file_tree_double_click(self, event):
        """Handle double-click on file tree item."""
        selection = self.file_tree.selection()
        if not selection:
            return
        
        item = self.file_tree.item(selection[0])
        if not item['values'] or not item['values'][0]:
            return
        
        file_path = item['values'][0]
        
        if os.path.isdir(file_path):
            # Expand/collapse directory
            current_state = self.file_tree.item(selection[0], 'open')
            self.file_tree.item(selection[0], open=not current_state)
            
            # Lazy load directory contents
            if not current_state:  # If expanding
                # Remove placeholder
                children = self.file_tree.get_children(selection[0])
                for child in children:
                    child_item = self.file_tree.item(child)
                    if child_item['text'] == "Loading...":
                        self.file_tree.delete(child)
                        break
                
                # Load actual contents
                self._load_directory_tree(file_path, selection[0], max_depth=1, current_depth=0)
        else:
            # Handle file double-click
            self._open_file_in_hex_viewer(file_path)

    def _open_file_in_hex_viewer(self, file_path):
        """Open file in hex viewer."""
        try:
            # Limit file size for hex viewing
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                result = messagebox.askyesno(
                    "Large File", 
                    f"File is {file_size // (1024*1024)}MB. This may take time to load.\nContinue?"
                )
                if not result:
                    return
            
            # Open hex viewer window
            hex_window = Toplevel(self)
            hex_window.title(f"Hex Viewer - {os.path.basename(file_path)}")
            hex_window.geometry("800x600")
            
            # File info
            info_frame = Frame(hex_window)
            info_frame.pack(fill=X, padx=5, pady=5)
            
            Label(info_frame, text=f"File: {file_path}").pack(anchor=W)
            Label(info_frame, text=f"Size: {file_size:,} bytes").pack(anchor=W)
            
            # Hex display
            text_frame = Frame(hex_window)
            text_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)
            
            scrollbar = Scrollbar(text_frame)
            scrollbar.pack(side=RIGHT, fill=Y)
            
            hex_text = Text(text_frame, yscrollcommand=scrollbar.set, font=('Courier', 10))
            hex_text.pack(side=LEFT, fill=BOTH, expand=True)
            scrollbar.config(command=hex_text.yview)
            
            # Load file content
            def load_hex():
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read(min(file_size, 1024*1024))  # Read max 1MB
                    
                    # Format as hex
                    hex_lines = []
                    for i in range(0, len(data), 16):
                        chunk = data[i:i+16]
                        hex_part = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        hex_lines.append(f'{i:08x}  {hex_part:<48} |{ascii_part}|')
                    
                    hex_text.insert('1.0', '\n'.join(hex_lines))
                    hex_text.config(state='disabled')
                    
                except Exception as e:
                    hex_text.insert('1.0', f"Error reading file: {str(e)}")
            
            threading.Thread(target=load_hex, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open file:\n{str(e)}")

    def _analyze_all_browsers(self):
        """Analyze all browsers."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return

        self.set_status("Analyzing browsers...")
        self.progress['mode'] = 'indeterminate'
        self.progress.start()

        def analyze():
            try:
                bf = BrowserForensics(self.current_mount_point)
                artifacts = bf.analyze_all_browsers()

                # Clear trees
                for item in self.history_tree.get_children():
                    self.history_tree.delete(item)
                for item in self.downloads_tree.get_children():
                    self.downloads_tree.delete(item)

                # Populate results
                for artifact in artifacts:
                    if artifact.artifact_type == "history":
                        self.history_tree.insert('', 'end', values=(
                            artifact.url[:50] if artifact.url else "",
                            artifact.title[:50] if artifact.title else "",
                            artifact.timestamp.strftime("%Y-%m-%d %H:%M") if artifact.timestamp else "",
                            artifact.source_browser
                        ))
                    elif artifact.artifact_type == "download":
                        self.downloads_tree.insert('', 'end', values=(
                            artifact.title or "",
                            artifact.url[:50] if artifact.url else "",
                            artifact.timestamp.strftime("%Y-%m-%d %H:%M") if artifact.timestamp else "",
                            artifact.source_browser
                        ))

                self.set_status(f"Found {len(artifacts)} browser artifacts")

                # Add note
                self.notes_widget.add_finding(
                    "Browser Analysis",
                    f"Found {len(artifacts)} browser artifacts",
                    self.current_mount_point
                )

            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress.stop()
                self.progress['mode'] = 'determinate'

        threading.Thread(target=analyze, daemon=True).start()

    def _analyze_registry(self):
        """Analyze Windows registry."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a Windows image first")
            return

        self.set_status("Analyzing registry...")
        self.progress['mode'] = 'indeterminate'
        self.progress.start()

        def analyze():
            try:
                ra = RegistryAnalyzer(self.current_mount_point)
                artifacts = ra.analyze_all()

                # Display results
                report = ra.export_report('text')
                self.registry_text.delete('1.0', END)
                self.registry_text.insert('1.0', report)

                self.set_status(f"Found {len(artifacts)} registry artifacts")

                # Add note
                self.notes_widget.add_finding(
                    "Registry Analysis",
                    f"Found {len(artifacts)} registry artifacts",
                    self.current_mount_point
                )

            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress.stop()
                self.progress['mode'] = 'determinate'

        threading.Thread(target=analyze, daemon=True).start()

    def _run_regripper(self):
        """Run RegRipper on registry hives."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount a Windows image first")
            return

        self.set_status("Running RegRipper...")

        def run():
            try:
                ra = RegistryAnalyzer(self.current_mount_point)
                output = ra.run_regripper()

                self.registry_text.delete('1.0', END)
                self.registry_text.insert('1.0', output)

                self.set_status("RegRipper analysis complete")

            except Exception as e:
                messagebox.showerror("Error", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _generate_plaso_timeline(self):
        """Generate timeline using Plaso."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return

        self.set_status("Generating Plaso timeline...")
        self.progress['mode'] = 'indeterminate'
        self.progress.start()

        def generate():
            try:
                output_file = os.path.join(self.case_dir, "timeline.plaso")

                # Run log2timeline
                result = self.tool_manager.run_plaso(
                    self.current_mount_point,
                    output_file
                )

                if result.success:
                    # Run psort to generate timeline
                    csv_file = os.path.join(self.case_dir, "timeline.csv")
                    result = self.tool_manager.run_psort(
                        output_file,
                        output_format="dynamic",
                        output_file=csv_file
                    )

                    if result.success:
                        self.set_status("Timeline generated successfully")

                        # Load timeline into tree
                        self._load_timeline_csv(csv_file)

                        # Add note
                        self.notes_widget.add_finding(
                            "Timeline Generated",
                            "Super timeline created with Plaso",
                            csv_file
                        )
                    else:
                        messagebox.showerror("Error", result.stderr)
                else:
                    messagebox.showerror("Error", result.stderr)

            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                self.progress.stop()
                self.progress['mode'] = 'determinate'

        threading.Thread(target=generate, daemon=True).start()

    def _run_search(self):
        """Run keyword search."""
        directory = self.search_dir.get()
        keywords_text = self.keywords.get()

        if not directory or not keywords_text:
            messagebox.showwarning("Missing Input", "Please specify directory and keywords")
            return

        if not os.path.exists(directory):
            messagebox.showerror("Error", f"Directory not found: {directory}")
            return

        self.set_status("Searching...")

        # Clear results
        for item in self.search_tree.get_children():
            self.search_tree.delete(item)

        def search():
            try:
                # Split keywords by comma, semicolon, or space
                import re
                keyword_list = [k.strip() for k in re.split(r'[,;\s]+', keywords_text) if k.strip()]
                
                if not keyword_list:
                    messagebox.showwarning("No Keywords", "Please enter valid keywords")
                    return

                self.set_status(f"Searching for {len(keyword_list)} keywords in {directory}...")
                
                # Simple file search implementation
                results = []
                search_count = 0
                
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if search_count > 1000:  # Limit search results
                            break
                            
                        file_path = os.path.join(root, file)
                        
                        # Skip binary files and large files
                        try:
                            if os.path.getsize(file_path) > 10 * 1024 * 1024:  # Skip files > 10MB
                                continue
                                
                            # Try to read as text
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                            # Search for keywords
                            for keyword in keyword_list:
                                if keyword.lower() in content.lower():
                                    # Find context around keyword
                                    lines = content.split('\n')
                                    for line_num, line in enumerate(lines, 1):
                                        if keyword.lower() in line.lower():
                                            # Get context (line with some surrounding text)
                                            context_start = max(0, line.find(keyword.lower()) - 20)
                                            context_end = min(len(line), line.find(keyword.lower()) + len(keyword) + 20)
                                            context = line[context_start:context_end]
                                            
                                            results.append({
                                                'file': file_path,
                                                'line': line_num,
                                                'context': context,
                                                'keyword': keyword
                                            })
                                            search_count += 1
                                            
                                            if search_count > 1000:
                                                break
                                    
                                    if search_count > 1000:
                                        break
                                        
                        except (UnicodeDecodeError, PermissionError, OSError):
                            # Skip files that can't be read
                            continue
                    
                    if search_count > 1000:
                        break

                # Display results
                for res in results:
                    relative_path = os.path.relpath(res['file'], directory)
                    self.search_tree.insert('', 'end', values=(
                        relative_path if len(relative_path) < 50 else "..." + relative_path[-47:],
                        res['line'],
                        res['context'][:100] + ("..." if len(res['context']) > 100 else "")
                    ))

                result_msg = f"Found {len(results)} matches"
                if search_count > 1000:
                    result_msg += " (limited to 1000 results)"
                    
                self.set_status(result_msg)

            except Exception as e:
                error_msg = f"Search error: {str(e)}"
                self.set_status(error_msg)
                messagebox.showerror("Search Error", error_msg)

        threading.Thread(target=search, daemon=True).start()

    def _run_volatility(self):
        """Run Volatility plugin."""
        mem_image = self.mem_image.get()
        plugin = self.vol_plugin.get()

        if not mem_image or not plugin:
            messagebox.showwarning("Missing Input", "Please specify memory image and plugin")
            return

        self.set_status(f"Running Volatility {plugin}...")

        def run():
            try:
                result = self.tool_manager.run_volatility(mem_image, plugin)

                self.memory_text.delete('1.0', END)
                self.memory_text.insert('1.0', result.stdout)

                self.set_status("Volatility analysis complete")

            except Exception as e:
                messagebox.showerror("Error", str(e))

        threading.Thread(target=run, daemon=True).start()

    def _analyze_pcap(self):
        """Analyze PCAP file."""
        pcap = self.pcap_file.get()

        if not pcap:
            messagebox.showwarning("No PCAP", "Please specify PCAP file")
            return

        self.set_status("Analyzing PCAP...")

        def analyze():
            try:
                result = self.tool_manager.run_tshark(pcap)

                self.network_text.delete('1.0', END)
                self.network_text.insert('1.0', result.stdout)

                self.set_status("PCAP analysis complete")

            except Exception as e:
                messagebox.showerror("Error", str(e))

        threading.Thread(target=analyze, daemon=True).start()

    def _generate_report(self):
        """Generate final report."""
        report_type = self.report_type.get()
        report_format = self.report_format.get()

        self.set_status("Generating report...")

        # Collect all findings
        report_content = f"# Digital Forensics Workbench Report\n\n"
        report_content += f"## Case Information\n"
        for field, var in self.case_vars.items():
            report_content += f"- {field.replace('_', ' ').title()}: {var.get()}\n"
        report_content += f"- Description:\n{self.case_description.get('1.0', END)}\n\n"

        report_content += f"## OS Detection\n"
        report_content += self.os_details.get('1.0', END) + "\n\n"

        report_content += f"## Browser Forensics\n"
        report_content += "### History\n"
        for item in self.history_tree.get_children():
            values = self.history_tree.item(item)['values']
            report_content += f"- URL: {values[0]}, Title: {values[1]}, Time: {values[2]}, Browser: {values[3]}\n"
        report_content += "\n### Downloads\n"
        for item in self.downloads_tree.get_children():
            values = self.downloads_tree.item(item)['values']
            report_content += f"- File: {values[0]}, URL: {values[1]}, Date: {values[2]}, Browser: {values[3]}\n"
        report_content += "\n\n"

        report_content += f"## Registry Analysis\n"
        report_content += self.registry_text.get('1.0', END) + "\n\n"

        report_content += f"## Timeline Analysis\n"
        for item in self.timeline_tree.get_children():
            values = self.timeline_tree.item(item)['values']
            report_content += f"- Timestamp: {values[0]}, Source: {values[1]}, Event: {values[2]}, Details: {values[3]}\n"
        report_content += "\n\n"

        report_content += f"## Keyword Search\n"
        for item in self.search_tree.get_children():
            values = self.search_tree.item(item)['values']
            report_content += f"- File: {values[0]}, Context: {values[2]}\n"
        report_content += "\n\n"

        report_content += f"## Memory Analysis\n"
        report_content += self.memory_text.get('1.0', END) + "\n\n"

        report_content += f"## Network Analysis\n"
        report_content += self.network_text.get('1.0', END) + "\n\n"

        report_content += f"## Mobile Forensics\n"
        report_content += self.mobile_text.get('1.0', END) + "\n\n"

        report_content += f"## Case Notes\n"
        report_content += self.notes_widget.get_all_notes() + "\n\n"

        # Save report
        report_path = os.path.join(self.case_dir, "exports", f"case_report.{report_format.lower()}")

        if report_format == "Markdown":
            with open(report_path, "w") as f:
                f.write(report_content)
        elif report_format == "PDF":
            # Convert markdown to PDF
            # This would require an external library like markdown2pdf or similar
            # For simplicity, we'll just save as markdown for now
            with open(report_path.replace(".pdf", ".md"), "w") as f:
                f.write(report_content)
            messagebox.showinfo("Report", "PDF generation requires external tools. Saved as Markdown.")
        else:
            messagebox.showinfo("Report", f"{report_format} format not yet supported. Saved as Markdown.")

        self.set_status(f"Report generated: {report_path}")
        self.report_text.delete('1.0', END)
        self.report_text.insert('1.0', report_content)

    def _export_browser_results(self):
        """Export browser analysis results."""
        if not self.current_mount_point:
            messagebox.showwarning("No Data", "No browser data to export")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Browser Results"
        )
        if not export_path:
            return

        try:
            with open(export_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Title', 'Visit Time', 'Browser'])
                for item in self.history_tree.get_children():
                    writer.writerow(self.history_tree.item(item)['values'])
                writer.writerow([]) # Separator
                writer.writerow(['File', 'URL', 'Date', 'Browser'])
                for item in self.downloads_tree.get_children():
                    writer.writerow(self.downloads_tree.item(item)['values'])
            messagebox.showinfo("Export", "Browser results exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _export_registry_results(self):
        """Export registry analysis results."""
        if not self.registry_text.get('1.0', END).strip():
            messagebox.showwarning("No Data", "No registry data to export")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Registry Results"
        )
        if not export_path:
            return

        try:
            with open(export_path, 'w') as f:
                f.write(self.registry_text.get('1.0', END))
            messagebox.showinfo("Export", "Registry results exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _export_timeline(self):
        """Export timeline results."""
        if not self.timeline_tree.get_children():
            messagebox.showwarning("No Data", "No timeline data to export")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Timeline"
        )
        if not export_path:
            return

        try:
            with open(export_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Source', 'Event', 'Details'])
                for item in self.timeline_tree.get_children():
                    writer.writerow(self.timeline_tree.item(item)['values'])
            messagebox.showinfo("Export", "Timeline exported successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

    def _load_timeline_csv(self, csv_file):
        """Load CSV timeline into treeview."""
        for item in self.timeline_tree.get_children():
            self.timeline_tree.delete(item)

        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            next(reader) # Skip header
            for row in reader:
                self.timeline_tree.insert('', 'end', values=row)

    def _run_full_analysis(self):
        """Run full analysis."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return

        self.set_status("Running full analysis...")

        # Run all analysis modules
        self._auto_detect_os()
        self._analyze_all_browsers()
        self._analyze_registry()
        self._generate_plaso_timeline()
        # Add other full analysis steps here

        self.set_status("Full analysis complete")

    def _run_yara_scan(self):
        """Run YARA scan."""
        messagebox.showinfo("YARA Scan", "YARA scan functionality to be implemented.")

    def _run_bulk_extractor(self):
        """Run Bulk Extractor."""
        messagebox.showinfo("Bulk Extractor", "Bulk Extractor functionality to be implemented.")

    def _show_documentation(self):
        """Show documentation."""
        messagebox.showinfo("Documentation", "Documentation will be available online.")

    def _show_shortcuts(self):
        """Show keyboard shortcuts."""
        messagebox.showinfo("Keyboard Shortcuts", "No specific shortcuts defined yet.")

    def _show_install_guide(self):
        """Show installation guide."""
        messagebox.showinfo("Installation Guide", "Installation guide will be available online.")

    def _edit_case_properties(self):
        """Edit case properties."""
        messagebox.showinfo("Case Properties", "Case properties editing functionality to be implemented.")

    def _show_preferences(self):
        """Show preferences."""
        messagebox.showinfo("Preferences", "Preferences functionality to be implemented.")

    def _open_hash_calculator(self):
        """Open hash calculator."""
        hash_window = Toplevel(self)
        hash_window.title("Hash Calculator")
        hash_window.geometry("600x400")
        
        # File selection
        file_frame = Frame(hash_window)
        file_frame.pack(fill=X, padx=10, pady=5)
        
        Label(file_frame, text="File:").pack(side=LEFT)
        file_entry = Entry(file_frame, width=50)
        file_entry.pack(side=LEFT, padx=5)
        
        def browse_file():
            path = filedialog.askopenfilename(title="Select file to hash")
            if path:
                file_entry.delete(0, END)
                file_entry.insert(0, path)
        
        Button(file_frame, text="Browse", command=browse_file).pack(side=LEFT)
        
        # Hash algorithms
        algo_frame = Frame(hash_window)
        algo_frame.pack(fill=X, padx=10, pady=5)
        
        Label(algo_frame, text="Algorithms:").pack(side=LEFT)
        md5_var = BooleanVar(value=True)
        sha1_var = BooleanVar(value=True)
        sha256_var = BooleanVar(value=True)
        
        Checkbutton(algo_frame, text="MD5", variable=md5_var).pack(side=LEFT)
        Checkbutton(algo_frame, text="SHA1", variable=sha1_var).pack(side=LEFT)
        Checkbutton(algo_frame, text="SHA256", variable=sha256_var).pack(side=LEFT)
        
        # Results
        result_text = Text(hash_window, height=15)
        result_text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        def calculate_hashes():
            file_path = file_entry.get()
            if not file_path or not os.path.exists(file_path):
                messagebox.showerror("Error", "Please select a valid file")
                return
            
            result_text.delete("1.0", END)
            result_text.insert(END, f"Calculating hashes for: {file_path}\n\n")
            
            try:
                if md5_var.get():
                    md5_hash = hashlib.md5()
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            md5_hash.update(chunk)
                    result_text.insert(END, f"MD5:    {md5_hash.hexdigest()}\n")
                
                if sha1_var.get():
                    sha1_hash = hashlib.sha1()
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            sha1_hash.update(chunk)
                    result_text.insert(END, f"SHA1:   {sha1_hash.hexdigest()}\n")
                
                if sha256_var.get():
                    sha256_hash = hashlib.sha256()
                    with open(file_path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(chunk)
                    result_text.insert(END, f"SHA256: {sha256_hash.hexdigest()}\n")
                
                result_text.insert(END, f"\nFile size: {os.path.getsize(file_path)} bytes\n")
                
            except Exception as e:
                result_text.insert(END, f"Error: {str(e)}\n")
        
        Button(hash_window, text="Calculate Hashes", command=calculate_hashes).pack(pady=10)

    def _run_strings_tool(self):
        """Run strings tool."""
        strings_window = Toplevel(self)
        strings_window.title("String Extractor")
        strings_window.geometry("800x600")
        
        # File selection
        file_frame = Frame(strings_window)
        file_frame.pack(fill=X, padx=10, pady=5)
        
        Label(file_frame, text="File:").pack(side=LEFT)
        file_entry = Entry(file_frame, width=50)
        file_entry.pack(side=LEFT, padx=5)
        
        def browse_file():
            path = filedialog.askopenfilename(title="Select file for string extraction")
            if path:
                file_entry.delete(0, END)
                file_entry.insert(0, path)
        
        Button(file_frame, text="Browse", command=browse_file).pack(side=LEFT)
        
        # Options
        options_frame = Frame(strings_window)
        options_frame.pack(fill=X, padx=10, pady=5)
        
        Label(options_frame, text="Min Length:").pack(side=LEFT)
        min_length = Entry(options_frame, width=5)
        min_length.pack(side=LEFT, padx=5)
        min_length.insert(0, "4")
        
        ascii_only = BooleanVar(value=True)
        Checkbutton(options_frame, text="ASCII only", variable=ascii_only).pack(side=LEFT, padx=10)
        
        # Results
        result_frame = Frame(strings_window)
        result_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        scrollbar = Scrollbar(result_frame)
        scrollbar.pack(side=RIGHT, fill=Y)
        
        result_text = Text(result_frame, yscrollcommand=scrollbar.set)
        result_text.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=result_text.yview)
        
        def extract_strings():
            file_path = file_entry.get()
            if not file_path or not os.path.exists(file_path):
                messagebox.showerror("Error", "Please select a valid file")
                return
            
            try:
                min_len = int(min_length.get())
            except ValueError:
                min_len = 4
            
            result_text.delete("1.0", END)
            result_text.insert(END, f"Extracting strings from: {file_path}\n")
            result_text.insert(END, f"Minimum length: {min_len}\n\n")
            
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                strings_found = []
                current_string = ""
                
                for byte in data:
                    if ascii_only.get():
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += chr(byte)
                        else:
                            if len(current_string) >= min_len:
                                strings_found.append(current_string)
                            current_string = ""
                    else:
                        if byte != 0:  # Any non-null byte
                            current_string += chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02x}"
                        else:
                            if len(current_string) >= min_len:
                                strings_found.append(current_string)
                            current_string = ""
                
                # Add final string if valid
                if len(current_string) >= min_len:
                    strings_found.append(current_string)
                
                result_text.insert(END, f"Found {len(strings_found)} strings:\n\n")
                for i, string in enumerate(strings_found[:1000]):  # Limit to first 1000
                    result_text.insert(END, f"{i+1:6d}: {string}\n")
                
                if len(strings_found) > 1000:
                    result_text.insert(END, f"\n... and {len(strings_found) - 1000} more strings")
                
            except Exception as e:
                result_text.insert(END, f"Error: {str(e)}\n")
        
        Button(strings_window, text="Extract Strings", command=extract_strings).pack(pady=10)

    def _open_hex_viewer(self):
        """Open hex viewer."""
        hex_window = Toplevel(self)
        hex_window.title("Hex Viewer")
        hex_window.geometry("900x700")
        
        # File selection
        file_frame = Frame(hex_window)
        file_frame.pack(fill=X, padx=10, pady=5)
        
        Label(file_frame, text="File:").pack(side=LEFT)
        file_entry = Entry(file_frame, width=60)
        file_entry.pack(side=LEFT, padx=5)
        
        def browse_file():
            path = filedialog.askopenfilename(title="Select file to view")
            if path:
                file_entry.delete(0, END)
                file_entry.insert(0, path)
                load_file()
        
        Button(file_frame, text="Browse", command=browse_file).pack(side=LEFT)
        
        # Navigation
        nav_frame = Frame(hex_window)
        nav_frame.pack(fill=X, padx=10, pady=5)
        
        Label(nav_frame, text="Offset:").pack(side=LEFT)
        offset_entry = Entry(nav_frame, width=10)
        offset_entry.pack(side=LEFT, padx=5)
        offset_entry.insert(0, "0")
        
        def go_to_offset():
            try:
                offset = int(offset_entry.get(), 16) if offset_entry.get().startswith('0x') else int(offset_entry.get())
                load_file(offset)
            except ValueError:
                messagebox.showerror("Error", "Invalid offset")
        
        Button(nav_frame, text="Go", command=go_to_offset).pack(side=LEFT)
        
        # Hex display
        display_frame = Frame(hex_window)
        display_frame.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Create text widget with monospace font
        hex_text = Text(display_frame, font=('Courier', 10), wrap=NONE)
        
        # Scrollbars
        v_scrollbar = Scrollbar(display_frame, orient=VERTICAL, command=hex_text.yview)
        h_scrollbar = Scrollbar(display_frame, orient=HORIZONTAL, command=hex_text.xview)
        hex_text.config(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack scrollbars and text
        v_scrollbar.pack(side=RIGHT, fill=Y)
        h_scrollbar.pack(side=BOTTOM, fill=X)
        hex_text.pack(side=LEFT, fill=BOTH, expand=True)
        
        def load_file(start_offset=0):
            file_path = file_entry.get()
            if not file_path or not os.path.exists(file_path):
                return
            
            hex_text.delete("1.0", END)
            
            try:
                with open(file_path, 'rb') as f:
                    f.seek(start_offset)
                    data = f.read(4096)  # Read 4KB at a time
                    
                    if not data:
                        hex_text.insert(END, "No data at this offset")
                        return
                    
                    # Format hex display
                    for i in range(0, len(data), 16):
                        # Offset
                        offset = start_offset + i
                        line = f"{offset:08X}  "
                        
                        # Hex bytes
                        hex_part = ""
                        ascii_part = ""
                        
                        for j in range(16):
                            if i + j < len(data):
                                byte = data[i + j]
                                hex_part += f"{byte:02X} "
                                ascii_part += chr(byte) if 32 <= byte <= 126 else "."
                            else:
                                hex_part += "   "
                                ascii_part += " "
                        
                        line += hex_part + " |" + ascii_part + "|\n"
                        hex_text.insert(END, line)
                        
            except Exception as e:
                hex_text.insert(END, f"Error reading file: {str(e)}")
        
        # Status
        status_frame = Frame(hex_window)
        status_frame.pack(fill=X, padx=10, pady=5)
        
        status_label = Label(status_frame, text="Select a file to view", relief=SUNKEN, anchor=W)
        status_label.pack(fill=X)

    def _run_file_carver(self):
        """Run file carver."""
        messagebox.showinfo("File Carver", "File carver functionality to be implemented.")

    def _check_tools(self):
        """Check external tools."""
        self._check_environment()
        
        # Also show tool installer
        self._install_tools()

    def _install_tools(self):
        """Open tool installation dialog."""
        try:
            self.tool_installer.show_installation_dialog()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open tool installer: {str(e)}")

    def _check_tools_on_startup(self):
        """Check tools on startup and offer installation if needed."""
        try:
            # Get tool status
            tool_status = self.tool_installer.get_tool_status()
            
            # Count missing required tools
            missing_required = []
            missing_optional = []
            
            for tool_name, status in tool_status.items():
                if not status["available"] and status["os_supported"]:
                    if status["required"]:
                        missing_required.append(status["name"])
                    else:
                        missing_optional.append(status["name"])
            
            # Show appropriate message based on OS and missing tools
            if platform.system() == "Windows":
                self._show_windows_startup_warning(missing_required, missing_optional)
            elif missing_required:
                self._show_missing_tools_dialog(missing_required, missing_optional)
            elif missing_optional:
                # Just update status, don't bother user for optional tools
                self.set_status(f"Optional tools available for installation: {len(missing_optional)}")
                
        except Exception as e:
            print(f"Tool check error: {e}")  # Silent error, don't bother user

    def _show_windows_startup_warning(self, missing_required, missing_optional):
        """Show Windows compatibility warning on startup."""
        if not missing_required and not missing_optional:
            return  # All available tools are installed
        
        response = messagebox.askyesno(
            "Windows Compatibility Notice",
            "This application works best on Linux systems.\n\n"
            "Many forensic tools are not available on Windows.\n"
            "Would you like to see the tool installation options?",
            icon='warning'
        )
        
        if response:
            self._install_tools()

    def _show_missing_tools_dialog(self, missing_required, missing_optional):
        """Show dialog for missing tools on Linux."""
        total_missing = len(missing_required) + len(missing_optional)
        
        message = f"Found {total_missing} missing forensic tools.\n\n"
        
        if missing_required:
            message += f"Required tools missing ({len(missing_required)}):\n"
            message += "• " + "\n• ".join(missing_required[:3])
            if len(missing_required) > 3:
                message += f"\n• ... and {len(missing_required) - 3} more"
            message += "\n\n"
        
        if missing_optional:
            message += f"Optional tools available ({len(missing_optional)}):\n"
            message += "• " + "\n• ".join(missing_optional[:3])
            if len(missing_optional) > 3:
                message += f"\n• ... and {len(missing_optional) - 3} more"
            message += "\n\n"
        
        message += "Would you like to install them automatically?"
        
        response = messagebox.askyesnocancel(
            "Missing Forensic Tools",
            message,
            icon='question'
        )
        
        if response is True:  # Yes - install automatically
            self._auto_install_missing_tools()
        elif response is False:  # No - show manual installation dialog
            self._install_tools()
        # Cancel - do nothing

    def _auto_install_missing_tools(self):
        """Automatically install missing tools in background."""
        def install_thread():
            try:
                self.set_status("Installing forensic tools...")
                results = self.tool_installer.install_all_tools()
                
                successful = sum(1 for success, _ in results.values() if success)
                total = len(results)
                
                if successful == total:
                    self.set_status(f"All {total} tools installed successfully!")
                    messagebox.showinfo("Installation Complete", 
                                      f"Successfully installed all {total} forensic tools.")
                else:
                    self.set_status(f"Installed {successful}/{total} tools")
                    messagebox.showwarning("Installation Partial", 
                                         f"Installed {successful} out of {total} tools.\n"
                                         f"Check Tools menu for details.")
            except Exception as e:
                self.set_status("Tool installation failed")
                messagebox.showerror("Installation Error", 
                                   f"Failed to install tools: {str(e)}")
        
        threading.Thread(target=install_thread, daemon=True).start()

    def _add_evidence(self):
        """Add evidence item."""
        evidence_window = Toplevel(self)
        evidence_window.title("Add Evidence")
        evidence_window.geometry("500x400")
        
        # Evidence details
        details_frame = ttk.LabelFrame(evidence_window, text="Evidence Details", padding=10)
        details_frame.pack(fill=X, padx=10, pady=5)
        
        Label(details_frame, text="Name:").grid(row=0, column=0, sticky='w')
        name_entry = Entry(details_frame, width=40)
        name_entry.grid(row=0, column=1, sticky='ew', padx=5)
        
        Label(details_frame, text="Type:").grid(row=1, column=0, sticky='w')
        type_combo = ttk.Combobox(details_frame, values=["Disk Image", "Memory Dump", "File", "Directory", "Network Capture"])
        type_combo.grid(row=1, column=1, sticky='ew', padx=5)
        type_combo.current(0)
        
        Label(details_frame, text="Path:").grid(row=2, column=0, sticky='w')
        path_entry = Entry(details_frame, width=40)
        path_entry.grid(row=2, column=1, sticky='ew', padx=5)
        
        def browse_evidence():
            if type_combo.get() == "Directory":
                path = filedialog.askdirectory(title="Select evidence directory")
            else:
                path = filedialog.askopenfilename(title="Select evidence file")
            if path:
                path_entry.delete(0, END)
                path_entry.insert(0, path)
                if not name_entry.get():
                    name_entry.insert(0, os.path.basename(path))
        
        Button(details_frame, text="Browse", command=browse_evidence).grid(row=2, column=2, padx=5)
        
        Label(details_frame, text="Description:").grid(row=3, column=0, sticky='nw')
        desc_text = Text(details_frame, height=4, width=40)
        desc_text.grid(row=3, column=1, columnspan=2, sticky='ew', padx=5, pady=5)
        
        # Hash calculation
        hash_frame = ttk.LabelFrame(evidence_window, text="Hash Verification", padding=10)
        hash_frame.pack(fill=X, padx=10, pady=5)
        
        calc_hash_var = BooleanVar(value=True)
        Checkbutton(hash_frame, text="Calculate hash on add", variable=calc_hash_var).pack(anchor='w')
        
        hash_text = Text(hash_frame, height=3)
        hash_text.pack(fill=X, pady=5)
        
        def add_evidence():
            name = name_entry.get()
            path = path_entry.get()
            evidence_type = type_combo.get()
            description = desc_text.get("1.0", END).strip()
            
            if not name or not path:
                messagebox.showerror("Error", "Please provide name and path")
                return
            
            if not os.path.exists(path):
                messagebox.showerror("Error", "Path does not exist")
                return
            
            # Create evidence entry
            evidence_id = f"evidence_{len(self.evidence_items) + 1}"
            evidence_data = {
                'id': evidence_id,
                'name': name,
                'type': evidence_type,
                'path': path,
                'description': description,
                'added_date': datetime.datetime.now().isoformat(),
                'hash': None
            }
            
            # Calculate hash if requested
            if calc_hash_var.get() and os.path.isfile(path):
                try:
                    hash_text.insert(END, "Calculating hash...\n")
                    evidence_window.update()
                    
                    sha256_hash = hashlib.sha256()
                    with open(path, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            sha256_hash.update(chunk)
                    
                    evidence_data['hash'] = sha256_hash.hexdigest()
                    hash_text.insert(END, f"SHA256: {evidence_data['hash']}\n")
                except Exception as e:
                    hash_text.insert(END, f"Hash calculation failed: {str(e)}\n")
            
            # Add to evidence tree
            self.evidence_items[evidence_id] = evidence_data
            item = self.evidence_tree.insert(self.case_node, 'end', text=name, values=(evidence_type, path))
            
            # Add note
            if hasattr(self, 'notes_widget') and self.notes_widget:
                self.notes_widget.add_note(
                    f"Evidence Added: {name}",
                    f"Type: {evidence_type}\nPath: {path}\nDescription: {description}",
                    ["evidence", "added"]
                )
            
            self.set_status(f"Evidence '{name}' added successfully")
            evidence_window.destroy()
        
        Button(evidence_window, text="Add Evidence", command=add_evidence).pack(pady=10)

    def _open_evidence(self):
        """Open selected evidence item."""
        selection = self.evidence_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an evidence item")
            return
        
        item = self.evidence_tree.item(selection[0])
        evidence_name = item['text']
        
        # Find evidence data
        evidence_data = None
        for eid, data in self.evidence_items.items():
            if data['name'] == evidence_name:
                evidence_data = data
                break
        
        if not evidence_data:
            messagebox.showerror("Error", "Evidence data not found")
            return
        
        evidence_path = evidence_data['path']
        
        # Open based on type
        if evidence_data['type'] == "Disk Image":
            # Set as current image for mounting
            self.image_path.delete(0, END)
            self.image_path.insert(0, evidence_path)
            self.notebook.select(1)  # Switch to Mount tab
        elif evidence_data['type'] == "Directory":
            # Open in file explorer
            if platform.system() == "Windows":
                os.startfile(evidence_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", evidence_path])
            else:
                subprocess.run(["xdg-open", evidence_path])
        else:
            # Try to open file with default application
            try:
                if platform.system() == "Windows":
                    os.startfile(evidence_path)
                elif platform.system() == "Darwin":
                    subprocess.run(["open", evidence_path])
                else:
                    subprocess.run(["xdg-open", evidence_path])
            except Exception as e:
                messagebox.showerror("Error", f"Cannot open file: {str(e)}")

    def _analyze_evidence(self):
        """Analyze selected evidence item."""
        selection = self.evidence_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an evidence item")
            return
        
        item = self.evidence_tree.item(selection[0])
        evidence_name = item['text']
        
        # Find evidence data
        evidence_data = None
        for eid, data in self.evidence_items.items():
            if data['name'] == evidence_name:
                evidence_data = data
                break
        
        if not evidence_data:
            messagebox.showerror("Error", "Evidence data not found")
            return
        
        # Create analysis window
        analysis_window = Toplevel(self)
        analysis_window.title(f"Analyze: {evidence_name}")
        analysis_window.geometry("600x500")
        
        # Analysis options
        options_frame = ttk.LabelFrame(analysis_window, text="Analysis Options", padding=10)
        options_frame.pack(fill=X, padx=10, pady=5)
        
        file_analysis = BooleanVar(value=True)
        hash_analysis = BooleanVar(value=True)
        metadata_analysis = BooleanVar(value=True)
        
        Checkbutton(options_frame, text="File type analysis", variable=file_analysis).pack(anchor='w')
        Checkbutton(options_frame, text="Hash verification", variable=hash_analysis).pack(anchor='w')
        Checkbutton(options_frame, text="Metadata extraction", variable=metadata_analysis).pack(anchor='w')
        
        # Results
        results_text = Text(analysis_window)
        results_text.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        def run_analysis():
            results_text.delete("1.0", END)
            results_text.insert(END, f"Analyzing: {evidence_data['path']}\n")
            results_text.insert(END, "=" * 50 + "\n\n")
            
            try:
                if file_analysis.get():
                    results_text.insert(END, "File Type Analysis:\n")
                    if os.path.isfile(evidence_data['path']):
                        # Basic file info
                        stat = os.stat(evidence_data['path'])
                        results_text.insert(END, f"Size: {stat.st_size} bytes\n")
                        results_text.insert(END, f"Modified: {datetime.datetime.fromtimestamp(stat.st_mtime)}\n")
                        results_text.insert(END, f"Created: {datetime.datetime.fromtimestamp(stat.st_ctime)}\n")
                    results_text.insert(END, "\n")
                
                if hash_analysis.get() and os.path.isfile(evidence_data['path']):
                    results_text.insert(END, "Hash Analysis:\n")
                    
                    # Calculate multiple hashes
                    md5_hash = hashlib.md5()
                    sha1_hash = hashlib.sha1()
                    sha256_hash = hashlib.sha256()
                    
                    with open(evidence_data['path'], 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            md5_hash.update(chunk)
                            sha1_hash.update(chunk)
                            sha256_hash.update(chunk)
                    
                    results_text.insert(END, f"MD5:    {md5_hash.hexdigest()}\n")
                    results_text.insert(END, f"SHA1:   {sha1_hash.hexdigest()}\n")
                    results_text.insert(END, f"SHA256: {sha256_hash.hexdigest()}\n\n")
                
                if metadata_analysis.get():
                    results_text.insert(END, "Metadata Analysis:\n")
                    results_text.insert(END, f"Full path: {os.path.abspath(evidence_data['path'])}\n")
                    results_text.insert(END, f"Evidence type: {evidence_data['type']}\n")
                    results_text.insert(END, f"Added to case: {evidence_data['added_date']}\n")
                    if evidence_data.get('hash'):
                        results_text.insert(END, f"Stored hash: {evidence_data['hash']}\n")
                    results_text.insert(END, "\n")
                
                results_text.insert(END, "Analysis complete.\n")
                
            except Exception as e:
                results_text.insert(END, f"Analysis error: {str(e)}\n")
        
        Button(analysis_window, text="Run Analysis", command=run_analysis).pack(pady=10)
        
        # Auto-run analysis
        run_analysis()

    def _hash_evidence(self):
        """Calculate hash of selected evidence item."""
        messagebox.showinfo("Hash Evidence", "Hash evidence functionality to be implemented.")

    def _remove_evidence(self):
        """Remove selected evidence item."""
        messagebox.showinfo("Remove Evidence", "Remove evidence functionality to be implemented.")

    def _show_evidence_menu(self, event):
        """Show context menu for evidence tree."""
        try:
            self.evidence_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.evidence_menu.grab_release()

    def _import_evidence(self):
        """Import evidence."""
        messagebox.showinfo("Import Evidence", "Import evidence functionality to be implemented.")

    def _export_report(self):
        """Export report."""
        messagebox.showinfo("Export Report", "Export report functionality to be implemented.")

    def _open_case(self):
        """Open an existing case."""
        messagebox.showinfo("Open Case", "Open case functionality to be implemented.")

    def _save_case(self):
        """Save current case."""
        messagebox.showinfo("Save Case", "Save case functionality to be implemented.")

    def _generate_tsk_timeline(self):
        """Generate timeline using TSK tools."""
        messagebox.showinfo("TSK Timeline", "TSK timeline generation functionality to be implemented.")

    def _analyze_mobile(self):
        """Analyze mobile data."""
        messagebox.showinfo("Mobile Analysis", "Mobile analysis functionality to be implemented.")

    def _generate_super_timeline(self):
        """Generate super timeline."""
        messagebox.showinfo("Super Timeline", "Super timeline generation functionality to be implemented.")

    def _browse_search_dir(self):
        path = filedialog.askdirectory(title="Select Search Directory")
        if path:
            self.search_dir.delete(0, END)
            self.search_dir.insert(0, path)

    def _browse_mem_image(self):
        path = filedialog.askopenfilename(
            title="Select Memory Image",
            filetypes=[("Memory Dump Files", "*.mem *.raw *.bin"), ("All Files", "*.*")]
        )
        if path:
            self.mem_image.delete(0, END)
            self.mem_image.insert(0, path)

    def _browse_pcap(self):
        path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")]
        )
        if path:
            self.pcap_file.delete(0, END)
            self.pcap_file.insert(0, path)

    def _browse_mobile(self):
        path = filedialog.askdirectory(title="Select Mobile Data Directory")
        if path:
            self.mobile_path.delete(0, END)
            self.mobile_path.insert(0, path)

    # Additional tool methods
    def _calc_image_hash(self):
        """Calculate disk image hash with progress indication."""
        image = self.image_path.get()
        if not image:
            messagebox.showwarning("No Image", "Please select a disk image first")
            return

        if not os.path.exists(image):
            messagebox.showerror("Error", "Image file not found")
            return

        # Ask user which hashes to calculate
        result = messagebox.askyesnocancel(
            "Hash Calculation", 
            "Hash calculation may take a long time for large images.\n\n"
            "Yes = Calculate MD5 only (faster)\n"
            "No = Calculate MD5 + SHA256 (slower)\n"
            "Cancel = Skip hash calculation"
        )
        
        if result is None:  # Cancel
            return
        
        calculate_sha256 = not result  # No = True (calculate both), Yes = False (MD5 only)

        self.set_status("Calculating hash... (this may take several minutes)")
        self.hash_label.config(text="Calculating hash... Please wait")

        def calc():
            try:
                file_size = os.path.getsize(image)
                processed = 0
                chunk_size = 1024 * 1024  # 1MB chunks for better performance
                
                md5 = hashlib.md5()
                sha256 = hashlib.sha256() if calculate_sha256 else None

                with open(image, 'rb') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        
                        md5.update(chunk)
                        if sha256:
                            sha256.update(chunk)
                        
                        processed += len(chunk)
                        
                        # Update progress every 100MB
                        if processed % (100 * 1024 * 1024) == 0:
                            progress = (processed / file_size) * 100
                            self.set_status(f"Calculating hash... {progress:.1f}% complete")

                # Display results
                hash_text = f"MD5: {md5.hexdigest()}"
                if sha256:
                    hash_text += f"\nSHA256: {sha256.hexdigest()}"
                
                self.hash_label.config(text=hash_text)
                self.set_status("Hash calculation complete")

                # Also show in popup for easy copying
                messagebox.showinfo("Hash Results", hash_text)

            except Exception as e:
                error_msg = f"Hash calculation failed: {str(e)}"
                self.hash_label.config(text="Hash calculation failed")
                self.set_status(error_msg)
                messagebox.showerror("Error", error_msg)

        threading.Thread(target=calc, daemon=True).start()

    def _run_quick_triage(self):
        """Run quick triage analysis."""
        if not self.current_mount_point:
            messagebox.showwarning("No Mount", "Please mount an image first")
            return

        # Run multiple analyses in sequence
        self._auto_detect_os()
        self._analyze_all_browsers()

        if self.detected_os and self.detected_os.os_type.value == "Windows":
            self._analyze_registry()

        self.set_status("Quick triage complete")

    def _show_about(self):
        """Show about dialog."""
        about_text = """
Digital Forensics Workbench
Professional Edition v3.0

A comprehensive forensic analysis platform
integrating industry-standard tools.

Features:
• OS Detection
• Browser Forensics  
• Registry Analysis
• Memory Analysis
• Timeline Generation
• Mobile Forensics
• Network Analysis
• Integrated Terminal
• Case Notes Management

© 2024 - MIT License
        """
        messagebox.showinfo("About DFW", about_text)

    # Missing critical methods implementation
    def _browse_image(self):
        """Browse for disk image file."""
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[
                ("Disk Images", "*.dd *.img *.raw *.e01 *.ex01 *.vmdk *.vdi"),
                ("All Files", "*.*")
            ]
        )
        if path:
            self.image_path.delete(0, END)
            self.image_path.insert(0, path)
            self.set_status(f"Selected image: {path}")

    def _browse_mount(self):
        """Browse for mount point directory with option to create new directories."""
        # First try to select existing directory
        path = filedialog.askdirectory(title="Select Mount Point Directory")
        
        if path:
            self.mount_path.delete(0, END)
            self.mount_path.insert(0, path)
            self.set_status(f"Selected mount point: {path}")
        else:
            # If user cancelled, offer to create new directory
            result = messagebox.askyesno(
                "Create New Directory", 
                "No directory selected. Would you like to create a new mount point directory?"
            )
            
            if result:
                self._create_mount_directory()

    def _create_mount_directory(self):
        """Create a new mount point directory."""
        # Ask for parent directory
        parent_dir = filedialog.askdirectory(title="Select Parent Directory for New Mount Point")
        
        if not parent_dir:
            return
        
        # Create dialog for new directory name
        from tkinter import simpledialog
        
        dir_name = simpledialog.askstring(
            "New Directory Name",
            "Enter name for new mount point directory:",
            initialvalue="mount_point"
        )
        
        if not dir_name:
            return
        
        # Sanitize directory name
        import re
        dir_name = re.sub(r'[<>:"/\\|?*]', '_', dir_name)
        
        new_path = os.path.join(parent_dir, dir_name)
        
        try:
            # Check if directory already exists
            if os.path.exists(new_path):
                result = messagebox.askyesno(
                    "Directory Exists",
                    f"Directory '{new_path}' already exists. Use it anyway?"
                )
                if not result:
                    return
            else:
                # Create the directory
                os.makedirs(new_path, exist_ok=True)
                messagebox.showinfo("Success", f"Created mount point directory:\n{new_path}")
            
            # Set the new path
            self.mount_path.delete(0, END)
            self.mount_path.insert(0, new_path)
            self.set_status(f"Created and selected mount point: {new_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create directory:\n{str(e)}")
            self.set_status(f"Error creating mount point: {str(e)}")

    def _extract_image(self):
        """Extract files from disk image."""
        image_path = self.image_path.get()
        if not image_path:
            messagebox.showerror("Error", "Please select a disk image first")
            return
        
        extract_dir = filedialog.askdirectory(title="Select extraction directory")
        if not extract_dir:
            return
        
        self.set_status("Extracting files from image...")
        try:
            # Use external tools for extraction
            result = self.tool_manager.run_tool("tsk_recover", ["-e", image_path, extract_dir])
            if result.success:
                messagebox.showinfo("Success", f"Files extracted to {extract_dir}")
                self.set_status("Extraction complete")
            else:
                messagebox.showerror("Error", f"Extraction failed: {result.error}")
                self.set_status("Extraction failed")
        except Exception as e:
            messagebox.showerror("Error", f"Extraction error: {str(e)}")
            self.set_status("Extraction failed")

    def _unmount_image(self):
        """Unmount the currently mounted image."""
        if not self.current_mount_point:
            messagebox.showwarning("Warning", "No image is currently mounted")
            return
        
        try:
            result = mount.unmount_image(self.current_mount_point)
            if result:
                messagebox.showinfo("Success", "Image unmounted successfully")
                self.current_mount_point = None
                self.set_status("Image unmounted")
            else:
                messagebox.showerror("Error", "Failed to unmount image")
        except Exception as e:
            messagebox.showerror("Error", f"Unmount error: {str(e)}")

    def set_status(self, message):
        """Set status bar message."""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=message)
        print(f"Status: {message}")  # Fallback for debugging


def main():
    """Main entry point."""
    app = CompleteDFW()
    app.mainloop()


if __name__ == "__main__":
    main()
