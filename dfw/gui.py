"""Graphical user interface for the Digital Forensics Workbench.

The GUI is built using Tkinter, which is available with most Python
installations. A tabbed notebook groups functionality into logical
sections: case information and environment checks, disk image mounting,
keyword search, memory forensics, network forensics and Android
analysis. Where necessary, long‑running operations are executed in
background threads to keep the interface responsive. Each action
invokes helper functions from the ``dfw`` package modules.

To launch the application directly run ``python -m dfw`` or ``python
dfw/main.py``. Ensure that required external tools (mmls, mount,
volatility3, tshark, etc.) are installed on your system for full
functionality.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from tkinter import (Tk, Toplevel, Frame, Label, Entry, Text, Button,
                     filedialog, END, Scrollbar, BooleanVar, Checkbutton)
from tkinter import ttk
from typing import Optional  # for type annotations
from tkinter.messagebox import showerror, showinfo

from . import env, mount, keywords, forensic_tools


class MainApp(Tk):
    """Main application class for the workbench GUI."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Digital Forensics Workbench")
        # Make the initial window slightly larger for better visibility.
        # The previous size was 900x600. Increase to 1100x700.
        self.geometry("1100x700")
        # Apply a slightly nicer theme where available
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            # Fallback silently if 'clam' theme is unavailable
            pass
        # Notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True)

        # Status bar
        self.status_var = ttk.Label(self, text="Ready", relief='sunken', anchor='w')
        self.status_var.pack(fill='x', side='bottom')

        # Tabs
        self.case_frame = Frame(notebook)
        self.mount_frame = Frame(notebook)
        self.search_frame = Frame(notebook)
        self.memory_frame = Frame(notebook)
        self.network_frame = Frame(notebook)
        self.android_frame = Frame(notebook)
        self.timeline_frame = Frame(notebook)

        notebook.add(self.case_frame, text="Case & Env")
        notebook.add(self.mount_frame, text="Mount")
        notebook.add(self.search_frame, text="Keyword Search")
        notebook.add(self.memory_frame, text="Memory")
        notebook.add(self.network_frame, text="Network")
        notebook.add(self.android_frame, text="Android")
        notebook.add(self.timeline_frame, text="File Timeline")

        self._init_case_tab()
        self._init_mount_tab()
        self._init_search_tab()
        self._init_memory_tab()
        self._init_network_tab()
        self._init_android_tab()
        self._init_timeline_tab()

    # Utility functions
    def set_status(self, message: str) -> None:
        """Update the status bar text."""
        self.status_var.config(text=message)
        self.update_idletasks()

    # Case & Environment Tab
    def _init_case_tab(self) -> None:
        frame = self.case_frame
        # Case metadata
        Label(frame, text="Case Name:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.case_name_var = Entry(frame, width=30)
        self.case_name_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Label(frame, text="Description:").grid(row=1, column=0, sticky='nw', padx=5, pady=5)
        self.case_desc_text = Text(frame, width=60, height=4)
        self.case_desc_text.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        # Evidence OS selection (row 2)
        Label(frame, text="Evidence OS:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        # Use a combobox to allow the user to specify the type of system being examined.
        os_options = ["Auto", "Windows", "Linux", "Android"]
        self.evidence_os_var = ttk.Combobox(frame, values=os_options, state="readonly", width=15)
        self.evidence_os_var.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        self.evidence_os_var.current(0)
        # Bind selection change to update other parts of the UI
        self.evidence_os_var.bind('<<ComboboxSelected>>', lambda e: self._update_memory_plugins())

        # Save Case button on its own row (row 3)
        Button(frame, text="Save Case", command=self._save_case).grid(row=3, column=1, sticky='e', padx=5, pady=5)

        # Environment information
        env_frame = Frame(frame, relief='groove', borderwidth=2)
        env_frame.grid(row=4, column=0, columnspan=2, sticky='nsew', padx=5, pady=10)
        Label(env_frame, text="Environment Information", font=('Arial', 10, 'bold')).pack(anchor='w', padx=5, pady=5)
        self.env_text = Text(env_frame, width=80, height=10, state='disabled')
        self.env_text.pack(fill='both', expand=True, padx=5, pady=5)
        Button(env_frame, text="Refresh", command=self._refresh_env).pack(anchor='e', padx=5, pady=5)

        frame.grid_rowconfigure(4, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    def _save_case(self) -> None:
        """Save basic case information to a JSON file in the current working directory."""
        name = self.case_name_var.get().strip()
        desc = self.case_desc_text.get('1.0', END).strip()
        if not name:
            showerror("Validation Error", "Case name cannot be empty.")
            return
        data = {
            'case_name': name,
            'description': desc,
        }
        filename = f"case_{name.replace(' ', '_')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        showinfo("Case Saved", f"Case information saved to {filename}")
        self.set_status(f"Case saved: {filename}")

    def _refresh_env(self) -> None:
        """Refresh and display environment information."""
        info = env.check_environment()
        self.env_text.config(state='normal')
        self.env_text.delete('1.0', END)
        self.env_text.insert(END, f"Operating System: {info['os_type']} {info['os_version']}\n")
        self.env_text.insert(END, f"Running under WSL: {'Yes' if info['is_wsl'] else 'No'}\n")
        self.env_text.insert(END, "Available Tools:\n")
        for tool, available in info['tools'].items():
            self.env_text.insert(END, f"  {tool}: {'Yes' if available else 'No'}\n")
        self.env_text.config(state='disabled')
        self.set_status("Environment information refreshed")

    # Mount Tab
    def _init_mount_tab(self) -> None:
        frame = self.mount_frame
        # Disk image file selection
        Label(frame, text="Disk Image (.dd/.img):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.image_path_var = Entry(frame, width=50)
        self.image_path_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_image).grid(row=0, column=2, padx=5, pady=5)

        Button(frame, text="List Partitions", command=self._list_partitions).grid(row=0, column=3, padx=5, pady=5)

        # Partition list
        self.partitions_tree = ttk.Treeview(frame, columns=('Index', 'Start', 'Length', 'Description'), show='headings', height=8)
        for col in ('Index', 'Start', 'Length', 'Description'):
            self.partitions_tree.heading(col, text=col)
            self.partitions_tree.column(col, width=100 if col != 'Description' else 200, anchor='w')
        self.partitions_tree.grid(row=1, column=0, columnspan=4, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.partitions_tree.yview)
        vsb.grid(row=1, column=4, sticky='ns')
        self.partitions_tree.configure(yscrollcommand=vsb.set)

        # Mount point selection
        Label(frame, text="Mount/Extraction Directory:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        self.mount_path_var = Entry(frame, width=50)
        self.mount_path_var.grid(row=2, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_mount_dir).grid(row=2, column=2, padx=5, pady=5)
        # Mount and Extract buttons
        self.mount_button = Button(frame, text="Mount (Linux)", command=self._mount_selected)
        self.mount_button.grid(row=3, column=0, padx=5, pady=10)
        self.extract_button = Button(frame, text="Extract (pytsk3)", command=self._extract_selected)
        self.extract_button.grid(row=3, column=1, padx=5, pady=10)
        self.unmount_button = Button(frame, text="Unmount", command=self._unmount)
        self.unmount_button.grid(row=3, column=2, padx=5, pady=10)

        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Track currently mounted directory
        self.current_mount_point: Optional[str] = None
        self.current_partition: Optional[mount.Partition] = None

        # Progress bar for mount/extract operations
        self.mount_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.mount_progress.grid(row=4, column=0, columnspan=4, sticky='ew', padx=5, pady=(0, 5))

    def _browse_image(self) -> None:
        path = filedialog.askopenfilename(title="Select Disk Image", filetypes=[("Disk Images", "*.dd *.img *.raw"), ("All Files", "*.*")])
        if path:
            self.image_path_var.delete(0, END)
            self.image_path_var.insert(0, path)
            self.set_status(f"Selected image: {os.path.basename(path)}")

    def _list_partitions(self) -> None:
        image_path = self.image_path_var.get().strip()
        if not image_path or not os.path.isfile(image_path):
            showerror("File Error", "Please select a valid disk image file.")
            return
        self.partitions_tree.delete(*self.partitions_tree.get_children())
        parts = mount.parse_partitions(image_path)
        if not parts:
            showinfo("No Partitions", "No partitions found or mmls not installed.")
            return
        for p in parts:
            self.partitions_tree.insert('', 'end', iid=str(p.index), values=(p.index, p.start_sector, p.length, p.description))
        self.set_status(f"Found {len(parts)} partitions.")
        # Store for later retrieval
        self._partitions_cache = {str(p.index): p for p in parts}

    def _browse_mount_dir(self) -> None:
        directory = filedialog.askdirectory(title="Select Mount/Extraction Directory")
        if directory:
            self.mount_path_var.delete(0, END)
            self.mount_path_var.insert(0, directory)
            self.set_status(f"Selected directory: {directory}")

    def _get_selected_partition(self) -> Optional[mount.Partition]:
        selected = self.partitions_tree.selection()
        if not selected:
            showerror("Selection Error", "Please select a partition from the list.")
            return None
        part_id = selected[0]
        return getattr(self, '_partitions_cache', {}).get(part_id)

    def _mount_selected(self) -> None:
        part = self._get_selected_partition()
        if not part:
            return
        mount_dir = self.mount_path_var.get().strip()
        image_path = self.image_path_var.get().strip()
        if not mount_dir:
            showerror("Directory Error", "Please select a mount directory.")
            return
        # Run mount in thread to avoid GUI lock
        def _mount():
            success = mount.mount_partition_linux(image_path, part, mount_dir)
            # Stop the progress bar when done (update on main thread)
            self.mount_progress.stop()
            if success:
                self.current_mount_point = mount_dir
                self.current_partition = part
                self.set_status(f"Mounted partition {part.index} at {mount_dir}")
                showinfo("Mount Success", f"Partition {part.index} mounted at {mount_dir}")
            else:
                self.set_status("Mount failed. Ensure you have appropriate privileges.")
                showerror("Mount Error", "Failed to mount partition. You may need root privileges or the mount tool might be unavailable.")
        # Start progress bar and spawn thread
        self.mount_progress.start()
        threading.Thread(target=_mount, daemon=True).start()

    def _extract_selected(self) -> None:
        part = self._get_selected_partition()
        if not part:
            return
        mount_dir = self.mount_path_var.get().strip()
        image_path = self.image_path_var.get().strip()
        if not mount_dir:
            showerror("Directory Error", "Please select an extraction directory.")
            return
        # Extraction can be time consuming; run in thread
        def _extract():
            try:
                ok = mount.extract_partition_to_directory(image_path, part, mount_dir)
                self.mount_progress.stop()
                if ok:
                    self.current_mount_point = mount_dir
                    self.current_partition = part
                    self.set_status(f"Extracted partition {part.index} to {mount_dir}")
                    showinfo("Extraction Complete", f"Partition {part.index} extracted to {mount_dir}")
                else:
                    self.set_status("Extraction failed")
                    showerror("Extraction Error", "Failed to extract partition. See console for details.")
            except Exception as e:
                self.mount_progress.stop()
                self.set_status("Extraction error")
                showerror("Extraction Error", str(e))
        # Start progress bar and spawn thread
        self.mount_progress.start()
        threading.Thread(target=_extract, daemon=True).start()

    def _unmount(self) -> None:
        if not self.current_mount_point:
            showinfo("Not Mounted", "No filesystem is currently mounted.")
            return
        def _do_unmount():
            success = mount.unmount(self.current_mount_point)
            if success:
                showinfo("Unmounted", f"Unmounted {self.current_mount_point}")
                self.set_status(f"Unmounted {self.current_mount_point}")
                self.current_mount_point = None
                self.current_partition = None
            else:
                showerror("Unmount Error", "Failed to unmount. Ensure the path is a mount point and you have privileges.")
                self.set_status("Unmount failed")
        threading.Thread(target=_do_unmount, daemon=True).start()

    # Keyword Search Tab
    def _init_search_tab(self) -> None:
        frame = self.search_frame
        # Directory selection
        Label(frame, text="Directory:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.search_dir_var = Entry(frame, width=50)
        self.search_dir_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_search_dir).grid(row=0, column=2, padx=5, pady=5)
        # Keywords entry
        Label(frame, text="Keywords (comma separated):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.keywords_var = Entry(frame, width=50)
        self.keywords_var.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Search", command=self._run_search).grid(row=1, column=2, padx=5, pady=5)
        # Results treeview
        self.search_tree = ttk.Treeview(frame, columns=('File', 'Keyword', 'Context'), show='headings', height=12)
        self.search_tree.heading('File', text='File')
        self.search_tree.heading('Keyword', text='Keyword')
        self.search_tree.heading('Context', text='Context')
        self.search_tree.column('File', width=250)
        self.search_tree.column('Keyword', width=100)
        self.search_tree.column('Context', width=400)
        self.search_tree.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.search_tree.yview)
        vsb.grid(row=2, column=3, sticky='ns')
        self.search_tree.configure(yscrollcommand=vsb.set)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        # Progress bar for search operations
        self.search_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.search_progress.grid(row=3, column=0, columnspan=3, sticky='ew', padx=5, pady=(0, 5))

    def _browse_search_dir(self) -> None:
        directory = filedialog.askdirectory(title="Select Directory to Search")
        if directory:
            self.search_dir_var.delete(0, END)
            self.search_dir_var.insert(0, directory)
            self.set_status(f"Selected search directory: {directory}")

    def _run_search(self) -> None:
        directory = self.search_dir_var.get().strip()
        if not directory or not os.path.isdir(directory):
            showerror("Directory Error", "Please select a valid directory to search.")
            return
        keywords_text = self.keywords_var.get().strip()
        if not keywords_text:
            showerror("Input Error", "Please enter at least one keyword.")
            return
        keywords_list = [k.strip() for k in keywords_text.split(',') if k.strip()]
        # Clear previous results
        self.search_tree.delete(*self.search_tree.get_children())
        self.set_status("Searching...")
        # Start progress bar
        self.search_progress.start()
        def _search():
            try:
                results = keywords.search_keywords(directory, keywords_list)
                self.search_progress.stop()
                for res in results:
                    self.search_tree.insert('', 'end', values=(res['file'], res['keyword'], res['context']))
                self.set_status(f"Search complete. {len(results)} hits found.")
            except Exception as e:
                self.search_progress.stop()
                showerror("Search Error", str(e))
                self.set_status("Search failed")
        threading.Thread(target=_search, daemon=True).start()

    # Memory Forensics Tab
    def _init_memory_tab(self) -> None:
        frame = self.memory_frame
        # Memory image selection
        Label(frame, text="Memory Image:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.mem_image_var = Entry(frame, width=50)
        self.mem_image_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_mem_image).grid(row=0, column=2, padx=5, pady=5)
        # Plugin selection
        Label(frame, text="Plugin:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        # Plugin combobox: options will be adjusted based on the selected evidence OS
        # Initialise the plugin combobox with no values.  We avoid
        # calling ``current(0)`` here because the list of plugins is
        # populated later based on the selected evidence OS.  Calling
        # ``current(0)`` on an empty combobox would raise a TclError.
        self.plugin_var = ttk.Combobox(frame, values=[], width=30)
        self.plugin_var.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Run", command=self._run_volatility).grid(row=1, column=2, padx=5, pady=5)
        # Output text area
        self.mem_output = Text(frame, wrap='none')
        self.mem_output.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.mem_output.yview)
        vsb.grid(row=2, column=3, sticky='ns')
        self.mem_output.configure(yscrollcommand=vsb.set)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        # Progress bar for memory analysis
        self.mem_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.mem_progress.grid(row=3, column=0, columnspan=3, sticky='ew', padx=5, pady=(0, 5))

        # Initialize plugin list based on current OS selection
        self._update_memory_plugins()

    def _browse_mem_image(self) -> None:
        path = filedialog.askopenfilename(title="Select Memory Image", filetypes=[("Memory Images", "*.*"), ("All Files", "*.*")])
        if path:
            self.mem_image_var.delete(0, END)
            self.mem_image_var.insert(0, path)
            self.set_status(f"Selected memory image: {os.path.basename(path)}")

    def _run_volatility(self) -> None:
        image = self.mem_image_var.get().strip()
        plugin = self.plugin_var.get().strip()
        if not image or not os.path.isfile(image):
            showerror("File Error", "Please select a valid memory image.")
            return
        self.mem_output.delete('1.0', END)
        self.set_status(f"Running Volatility plugin {plugin}...")
        # Start progress bar
        self.mem_progress.start()
        def _run():
            try:
                output = forensic_tools.run_volatility(image, plugin)
                self.mem_progress.stop()
                self.mem_output.insert('1.0', output)
                self.set_status("Volatility analysis complete")
            except forensic_tools.ToolUnavailableError as e:
                self.mem_progress.stop()
                showerror("Tool Error", str(e))
                self.set_status("Volatility not available")
            except Exception as e:
                self.mem_progress.stop()
                showerror("Error", str(e))
                self.set_status("Volatility run failed")
        threading.Thread(target=_run, daemon=True).start()

    # Helper to update available memory analysis plugins based on selected evidence OS
    def _update_memory_plugins(self) -> None:
        """Update the memory plugin combobox according to the selected evidence OS."""
        # Determine the selected OS; default to 'Auto' if variable not yet initialised
        os_choice = getattr(self, 'evidence_os_var', None)
        selected = os_choice.get() if os_choice else 'Auto'
        # Define plugin lists for supported OSes
        windows_plugins = ['windows.pslist', 'windows.netscan', 'windows.dlllist', 'windows.handles']
        linux_plugins = ['linux.pslist', 'linux.netstat', 'linux.bash']
        if selected == 'Windows':
            values = windows_plugins
        elif selected == 'Linux':
            values = linux_plugins
        elif selected == 'Android':
            # No memory plugins applicable for Android in this implementation
            values = []
        else:
            # Auto or unknown: show all available plugins
            values = windows_plugins + linux_plugins
        # Update the combobox values and set the first item as selected if list is not empty
        self.plugin_var['values'] = values
        if values:
            self.plugin_var.current(0)
        else:
            # Clear selection if there are no plugins
            self.plugin_var.set('')

    # Network Forensics Tab
    def _init_network_tab(self) -> None:
        frame = self.network_frame
        # PCAP selection
        Label(frame, text="PCAP File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.pcap_var = Entry(frame, width=50)
        self.pcap_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_pcap).grid(row=0, column=2, padx=5, pady=5)
        # Summary checkbox
        self.summary_var = BooleanVar(value=True)
        Checkbutton(frame, text="Per‑Host Summary", variable=self.summary_var).grid(row=1, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Run", command=self._run_tshark).grid(row=1, column=2, padx=5, pady=5)
        # Output text
        self.pcap_output = Text(frame, wrap='none')
        self.pcap_output.grid(row=2, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.pcap_output.yview)
        vsb.grid(row=2, column=3, sticky='ns')
        self.pcap_output.configure(yscrollcommand=vsb.set)
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        # Progress bar for network analysis
        self.tshark_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.tshark_progress.grid(row=3, column=0, columnspan=3, sticky='ew', padx=5, pady=(0, 5))

    def _browse_pcap(self) -> None:
        path = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap *.pcapng"), ("All Files", "*.*")])
        if path:
            self.pcap_var.delete(0, END)
            self.pcap_var.insert(0, path)
            self.set_status(f"Selected PCAP: {os.path.basename(path)}")

    def _run_tshark(self) -> None:
        pcap = self.pcap_var.get().strip()
        if not pcap or not os.path.isfile(pcap):
            showerror("File Error", "Please select a valid PCAP file.")
            return
        summary = self.summary_var.get()
        self.pcap_output.delete('1.0', END)
        self.set_status("Running tshark analysis...")
        # Start progress bar
        self.tshark_progress.start()
        def _run():
            try:
                output = forensic_tools.run_tshark(pcap, summary)
                self.tshark_progress.stop()
                self.pcap_output.insert('1.0', output)
                self.set_status("Tshark analysis complete")
            except forensic_tools.ToolUnavailableError as e:
                self.tshark_progress.stop()
                showerror("Tool Error", str(e))
                self.set_status("tshark not available")
            except Exception as e:
                self.tshark_progress.stop()
                showerror("Error", str(e))
                self.set_status("tshark run failed")
        threading.Thread(target=_run, daemon=True).start()

    # Android Forensics Tab
    def _init_android_tab(self) -> None:
        frame = self.android_frame
        # Input path selection
        Label(frame, text="Android Input Path:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.android_input_var = Entry(frame, width=50)
        self.android_input_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_android_input).grid(row=0, column=2, padx=5, pady=5)
        # Output directory selection
        Label(frame, text="Output Directory:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.android_output_var = Entry(frame, width=50)
        self.android_output_var.grid(row=1, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_android_output).grid(row=1, column=2, padx=5, pady=5)
        Button(frame, text="Run ALEAPP", command=self._run_aleapp).grid(row=2, column=2, padx=5, pady=5)
        # Output text
        self.android_output_text = Text(frame, wrap='none')
        self.android_output_text.grid(row=3, column=0, columnspan=3, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.android_output_text.yview)
        vsb.grid(row=3, column=3, sticky='ns')
        self.android_output_text.configure(yscrollcommand=vsb.set)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        # Progress bar for Android analysis
        self.aleapp_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.aleapp_progress.grid(row=4, column=0, columnspan=3, sticky='ew', padx=5, pady=(0, 5))

    def _browse_android_input(self) -> None:
        path = filedialog.askdirectory(title="Select Android Data Path")
        if path:
            self.android_input_var.delete(0, END)
            self.android_input_var.insert(0, path)
            self.set_status(f"Selected Android input: {path}")

    def _browse_android_output(self) -> None:
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.android_output_var.delete(0, END)
            self.android_output_var.insert(0, path)
            self.set_status(f"Selected Android output: {path}")

    def _run_aleapp(self) -> None:
        input_path = self.android_input_var.get().strip()
        output_dir = self.android_output_var.get().strip()
        if not input_path or not os.path.isdir(input_path):
            showerror("Input Error", "Please select a valid Android input path.")
            return
        if not output_dir:
            showerror("Output Error", "Please select an output directory.")
            return
        self.android_output_text.delete('1.0', END)
        self.set_status("Running ALEAPP...")
        # Start progress bar
        self.aleapp_progress.start()
        def _run():
            try:
                output = forensic_tools.run_aleapp(input_path, output_dir)
                self.aleapp_progress.stop()
                self.android_output_text.insert('1.0', output)
                self.set_status("ALEAPP analysis complete")
            except forensic_tools.ToolUnavailableError as e:
                self.aleapp_progress.stop()
                showerror("Tool Error", str(e))
                self.set_status("ALEAPP not available")
            except Exception as e:
                self.aleapp_progress.stop()
                showerror("Error", str(e))
                self.set_status("ALEAPP run failed")
        threading.Thread(target=_run, daemon=True).start()

    # Plaso Timeline Tab
    def _init_timeline_tab(self) -> None:
        """Initialise the file timeline tab.

        This tab allows the user to select a directory and generate a
        timeline based on file metadata (access, modification and
        creation/change times). The results are displayed in a text
        widget and can be copied or saved by the user.
        """
        frame = self.timeline_frame
        # Directory selection
        Label(frame, text="Directory:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.timeline_dir_var = Entry(frame, width=50)
        self.timeline_dir_var.grid(row=0, column=1, sticky='w', padx=5, pady=5)
        Button(frame, text="Browse", command=self._browse_timeline_dir).grid(row=0, column=2, padx=5, pady=5)
        Button(frame, text="Generate Timeline", command=self._run_timeline).grid(row=0, column=3, padx=5, pady=5)
        # Output text area
        self.timeline_output = Text(frame, wrap='none')
        self.timeline_output.grid(row=1, column=0, columnspan=4, sticky='nsew', padx=5, pady=5)
        vsb = Scrollbar(frame, orient='vertical', command=self.timeline_output.yview)
        vsb.grid(row=1, column=4, sticky='ns')
        self.timeline_output.configure(yscrollcommand=vsb.set)
        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        # Progress bar
        self.timeline_progress = ttk.Progressbar(frame, mode='indeterminate')
        self.timeline_progress.grid(row=2, column=0, columnspan=4, sticky='ew', padx=5, pady=(0, 5))

    def _browse_timeline_dir(self) -> None:
        """Browse for a directory to generate a timeline from."""
        path = filedialog.askdirectory(title="Select Directory for Timeline")
        if path:
            self.timeline_dir_var.delete(0, END)
            self.timeline_dir_var.insert(0, path)
            self.set_status(f"Selected directory: {path}")

    def _run_timeline(self) -> None:
        """Run the timeline generation on the selected directory."""
        directory = self.timeline_dir_var.get().strip()
        if not directory or not os.path.isdir(directory):
            showerror("Directory Error", "Please select a valid directory.")
            return
        self.timeline_output.delete('1.0', END)
        self.set_status("Generating file timeline…")
        # Start the progress bar
        self.timeline_progress.start()
        def _run():
            try:
                output = forensic_tools.generate_file_timeline(directory)
                self.timeline_progress.stop()
                self.timeline_output.insert('1.0', output)
                self.set_status("Timeline generation complete")
            except Exception as e:
                self.timeline_progress.stop()
                showerror("Error", str(e))
                self.set_status("Timeline generation failed")
        threading.Thread(target=_run, daemon=True).start()


def run_app() -> None:
    """Entry point to start the Tkinter application."""
    app = MainApp()
    app.mainloop()