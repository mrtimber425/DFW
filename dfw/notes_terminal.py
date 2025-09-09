"""Note-taking and terminal integration for Digital Forensics Workbench.

This module provides case notes management and an embedded terminal for
running commands directly from the application.
"""

import os
import json
import datetime
import subprocess
import threading
import queue
import platform
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import hashlib
import base64
from tkinter import *
from tkinter import ttk, messagebox, filedialog
import tkinter.font as tkfont


@dataclass
class CaseNote:
    """Individual case note entry."""
    id: str
    timestamp: datetime.datetime
    title: str
    content: str
    tags: List[str]
    evidence_refs: List[str]  # References to evidence items
    attachments: List[str]  # File paths to attachments
    category: str  # Finding, Analysis, Observation, etc.
    priority: str  # High, Medium, Low
    author: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'title': self.title,
            'content': self.content,
            'tags': self.tags,
            'evidence_refs': self.evidence_refs,
            'attachments': self.attachments,
            'category': self.category,
            'priority': self.priority,
            'author': self.author
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'CaseNote':
        """Create from dictionary."""
        data['timestamp'] = datetime.datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class CaseNotesManager:
    """Manages case notes and documentation."""

    def __init__(self, case_dir: str):
        """Initialize notes manager for a case.

        Args:
            case_dir: Directory for the case
        """
        self.case_dir = Path(case_dir)
        self.notes_dir = self.case_dir / "notes"
        self.notes_dir.mkdir(parents=True, exist_ok=True)
        self.notes_file = self.notes_dir / "case_notes.json"
        self.notes = self._load_notes()

    def _load_notes(self) -> List[CaseNote]:
        """Load existing notes from file."""
        if self.notes_file.exists():
            try:
                with open(self.notes_file, 'r') as f:
                    data = json.load(f)
                return [CaseNote.from_dict(note) for note in data]
            except Exception as e:
                print(f"Error loading notes: {e}")
        return []

    def _save_notes(self) -> None:
        """Save notes to file."""
        try:
            data = [note.to_dict() for note in self.notes]
            with open(self.notes_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving notes: {e}")

    def add_note(self, title: str, content: str, category: str = "Observation",
                 priority: str = "Medium", tags: Optional[List[str]] = None,
                 evidence_refs: Optional[List[str]] = None,
                 attachments: Optional[List[str]] = None,
                 author: str = "Investigator") -> CaseNote:
        """Add a new note.

        Returns:
            Created CaseNote object
        """
        note_id = hashlib.md5(
            f"{datetime.datetime.now().isoformat()}{title}".encode()
        ).hexdigest()[:8]

        note = CaseNote(
            id=note_id,
            timestamp=datetime.datetime.now(),
            title=title,
            content=content,
            tags=tags or [],
            evidence_refs=evidence_refs or [],
            attachments=attachments or [],
            category=category,
            priority=priority,
            author=author
        )

        self.notes.append(note)
        self._save_notes()
        return note

    def update_note(self, note_id: str, **kwargs) -> Optional[CaseNote]:
        """Update an existing note."""
        for note in self.notes:
            if note.id == note_id:
                for key, value in kwargs.items():
                    if hasattr(note, key):
                        setattr(note, key, value)
                self._save_notes()
                return note
        return None

    def delete_note(self, note_id: str) -> bool:
        """Delete a note."""
        for i, note in enumerate(self.notes):
            if note.id == note_id:
                del self.notes[i]
                self._save_notes()
                return True
        return False

    def get_note(self, note_id: str) -> Optional[CaseNote]:
        """Get a specific note."""
        for note in self.notes:
            if note.id == note_id:
                return note
        return None

    def search_notes(self, query: str = None, tags: List[str] = None,
                     category: str = None, priority: str = None) -> List[CaseNote]:
        """Search notes with filters."""
        results = self.notes

        if query:
            query_lower = query.lower()
            results = [n for n in results
                       if query_lower in n.title.lower() or
                       query_lower in n.content.lower()]

        if tags:
            results = [n for n in results
                       if any(tag in n.tags for tag in tags)]

        if category:
            results = [n for n in results if n.category == category]

        if priority:
            results = [n for n in results if n.priority == priority]

        return results

    def export_notes(self, format: str = "markdown",
                     output_file: Optional[str] = None) -> str:
        """Export notes to various formats.

        Args:
            format: Export format (markdown, html, pdf, docx)
            output_file: Optional output file path

        Returns:
            Exported content as string
        """
        if format == "markdown":
            content = self._export_markdown()
        elif format == "html":
            content = self._export_html()
        elif format == "json":
            content = json.dumps([n.to_dict() for n in self.notes], indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(content)

        return content

    def _export_markdown(self) -> str:
        """Export notes as Markdown."""
        lines = ["# Case Notes\n"]
        lines.append(f"Generated: {datetime.datetime.now().isoformat()}\n")
        lines.append(f"Total Notes: {len(self.notes)}\n")
        lines.append("\n---\n")

        # Group by category
        by_category = {}
        for note in sorted(self.notes, key=lambda n: n.timestamp, reverse=True):
            if note.category not in by_category:
                by_category[note.category] = []
            by_category[note.category].append(note)

        for category, notes in by_category.items():
            lines.append(f"\n## {category}\n")

            for note in notes:
                lines.append(f"\n### {note.title}\n")
                lines.append(f"**ID:** {note.id}  \n")
                lines.append(f"**Time:** {note.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  \n")
                lines.append(f"**Priority:** {note.priority}  \n")
                lines.append(f"**Author:** {note.author}  \n")

                if note.tags:
                    lines.append(f"**Tags:** {', '.join(note.tags)}  \n")

                if note.evidence_refs:
                    lines.append(f"**Evidence:** {', '.join(note.evidence_refs)}  \n")

                lines.append(f"\n{note.content}\n")

                if note.attachments:
                    lines.append("\n**Attachments:**\n")
                    for attachment in note.attachments:
                        lines.append(f"- {attachment}\n")

                lines.append("\n---\n")

        return "".join(lines)

    def _export_html(self) -> str:
        """Export notes as HTML."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Case Notes</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #4CAF50; margin-top: 30px; }
        h3 { color: #666; background: #f5f5f5; padding: 10px; }
        .note { margin: 20px 0; padding: 15px; border-left: 4px solid #4CAF50; background: #fafafa; }
        .metadata { color: #888; font-size: 0.9em; margin-bottom: 10px; }
        .priority-high { border-left-color: #f44336; }
        .priority-medium { border-left-color: #ff9800; }
        .priority-low { border-left-color: #4CAF50; }
        .tags { margin-top: 10px; }
        .tag { display: inline-block; background: #e0e0e0; padding: 3px 8px; margin: 2px; border-radius: 3px; font-size: 0.85em; }
    </style>
</head>
<body>
    <h1>Case Notes Report</h1>
    <p>Generated: {}</p>
    <p>Total Notes: {}</p>
""".format(datetime.datetime.now().isoformat(), len(self.notes))

        # Group by category
        by_category = {}
        for note in sorted(self.notes, key=lambda n: n.timestamp, reverse=True):
            if note.category not in by_category:
                by_category[note.category] = []
            by_category[note.category].append(note)

        for category, notes in by_category.items():
            html += f"<h2>{category}</h2>\n"

            for note in notes:
                priority_class = f"priority-{note.priority.lower()}"
                html += f'<div class="note {priority_class}">\n'
                html += f'<h3>{note.title}</h3>\n'
                html += f'<div class="metadata">\n'
                html += f'ID: {note.id} | '
                html += f'Time: {note.timestamp.strftime("%Y-%m-%d %H:%M:%S")} | '
                html += f'Priority: {note.priority} | '
                html += f'Author: {note.author}\n'
                html += '</div>\n'

                # Content with preserved formatting
                content_html = note.content.replace('\n', '<br>\n')
                html += f'<p>{content_html}</p>\n'

                if note.tags:
                    html += '<div class="tags">\n'
                    for tag in note.tags:
                        html += f'<span class="tag">{tag}</span>\n'
                    html += '</div>\n'

                html += '</div>\n'

        html += """
</body>
</html>
"""
        return html


class EmbeddedTerminal(Frame):
    """Embedded terminal widget for running commands."""

    def __init__(self, parent, **kwargs):
        """Initialize embedded terminal.

        Args:
            parent: Parent widget
            **kwargs: Additional frame options
        """
        super().__init__(parent, **kwargs)

        self.os_type = platform.system()
        self.current_dir = os.getcwd()
        self.command_history = []
        self.history_index = -1
        self.process = None
        self.output_queue = queue.Queue()

        self._create_widgets()
        self._setup_shell()

    def _create_widgets(self):
        """Create terminal UI widgets."""
        # Terminal output area
        output_frame = Frame(self, bg='black')
        output_frame.pack(fill=BOTH, expand=True)

        # Text widget with scrollbar
        scrollbar = Scrollbar(output_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Configure terminal font and colors
        terminal_font = tkfont.Font(family='Courier', size=10)

        self.output_text = Text(
            output_frame,
            bg='black',
            fg='lime',
            insertbackground='lime',
            font=terminal_font,
            wrap=WORD,
            yscrollcommand=scrollbar.set
        )
        self.output_text.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=self.output_text.yview)

        # Command input area
        input_frame = Frame(self, bg='black')
        input_frame.pack(fill=X)

        # Prompt label
        self.prompt_label = Label(
            input_frame,
            text=f"{self.current_dir}> ",
            bg='black',
            fg='lime',
            font=terminal_font
        )
        self.prompt_label.pack(side=LEFT)

        # Command entry
        self.command_entry = Entry(
            input_frame,
            bg='black',
            fg='lime',
            insertbackground='lime',
            font=terminal_font
        )
        self.command_entry.pack(side=LEFT, fill=X, expand=True)

        # Bind events
        self.command_entry.bind('<Return>', self._execute_command)
        self.command_entry.bind('<Up>', self._history_up)
        self.command_entry.bind('<Down>', self._history_down)
        self.command_entry.bind('<Tab>', self._autocomplete)

        # Control buttons
        control_frame = Frame(self, bg='gray20')
        control_frame.pack(fill=X)

        Button(control_frame, text="Clear", command=self._clear_terminal,
               bg='gray30', fg='white').pack(side=LEFT, padx=2)
        Button(control_frame, text="Kill Process", command=self._kill_process,
               bg='gray30', fg='white').pack(side=LEFT, padx=2)
        Button(control_frame, text="New Shell", command=self._setup_shell,
               bg='gray30', fg='white').pack(side=LEFT, padx=2)

        # Terminal type selector
        self.terminal_type = StringVar(value="system")
        terminal_types = ["system", "python", "powershell", "bash"]

        ttk.Combobox(control_frame, textvariable=self.terminal_type,
                     values=terminal_types, width=15).pack(side=RIGHT, padx=5)

    def _setup_shell(self):
        """Set up the shell process."""
        if self.process:
            self._kill_process()

        # Welcome message
        self._write_output("Digital Forensics Workbench - Embedded Terminal\n")
        self._write_output(f"OS: {self.os_type}\n")
        self._write_output(f"Current Directory: {self.current_dir}\n")
        self._write_output("-" * 60 + "\n")

        # Update prompt
        self._update_prompt()

    def _execute_command(self, event=None):
        """Execute entered command."""
        command = self.command_entry.get().strip()
        if not command:
            return

        # Add to history
        self.command_history.append(command)
        self.history_index = len(self.command_history)

        # Clear input
        self.command_entry.delete(0, END)

        # Display command
        self._write_output(f"{self.current_dir}> {command}\n", 'command')

        # Handle special commands
        if command.lower() in ['exit', 'quit']:
            self._write_output("Use the GUI to close the terminal.\n")
            return
        elif command.startswith('cd '):
            self._change_directory(command[3:].strip())
            return
        elif command == 'clear' or command == 'cls':
            self._clear_terminal()
            return
        elif command == 'pwd':
            self._write_output(f"{self.current_dir}\n")
            return

        # Execute command based on terminal type
        terminal_type = self.terminal_type.get()

        if terminal_type == "python":
            self._execute_python(command)
        else:
            self._execute_system_command(command)

    def _execute_system_command(self, command):
        """Execute system command."""

        def run_command():
            try:
                # Determine shell based on OS
                if self.os_type == "Windows":
                    shell_cmd = ["cmd", "/c", command]
                else:
                    shell_cmd = ["bash", "-c", command]

                # Run command
                process = subprocess.Popen(
                    shell_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=self.current_dir
                )

                # Read output
                stdout, stderr = process.communicate()

                # Queue output for display
                if stdout:
                    self.output_queue.put(('stdout', stdout))
                if stderr:
                    self.output_queue.put(('stderr', stderr))

            except Exception as e:
                self.output_queue.put(('error', str(e)))

            # Schedule GUI update
            self.after(0, self._process_output_queue)

        # Run in thread
        thread = threading.Thread(target=run_command)
        thread.daemon = True
        thread.start()

    def _execute_python(self, command):
        """Execute Python code."""
        try:
            # Execute in local namespace
            result = eval(command)
            if result is not None:
                self._write_output(f"{result}\n")
        except SyntaxError:
            try:
                exec(command)
            except Exception as e:
                self._write_output(f"Error: {e}\n", 'error')
        except Exception as e:
            self._write_output(f"Error: {e}\n", 'error')

    def _process_output_queue(self):
        """Process queued output from background thread."""
        try:
            while True:
                output_type, content = self.output_queue.get_nowait()

                if output_type == 'stdout':
                    self._write_output(content)
                elif output_type == 'stderr':
                    self._write_output(content, 'error')
                elif output_type == 'error':
                    self._write_output(f"Error: {content}\n", 'error')

        except queue.Empty:
            pass

    def _write_output(self, text, tag=None):
        """Write text to terminal output."""
        self.output_text.insert(END, text)

        if tag == 'error':
            # Color error text red
            start = self.output_text.index("end-2c linestart")
            end = self.output_text.index("end-1c")
            self.output_text.tag_add("error", start, end)
            self.output_text.tag_config("error", foreground="red")
        elif tag == 'command':
            # Color commands yellow
            start = self.output_text.index("end-2c linestart")
            end = self.output_text.index("end-1c")
            self.output_text.tag_add("command", start, end)
            self.output_text.tag_config("command", foreground="yellow")

        # Auto-scroll to bottom
        self.output_text.see(END)

    def _clear_terminal(self):
        """Clear terminal output."""
        self.output_text.delete('1.0', END)
        self._setup_shell()

    def _kill_process(self):
        """Kill running process."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self._write_output("\nProcess terminated.\n", 'error')
            self.process = None

    def _change_directory(self, path):
        """Change current directory."""
        try:
            # Expand path
            path = os.path.expanduser(path)
            if not os.path.isabs(path):
                path = os.path.join(self.current_dir, path)

            # Normalize path
            path = os.path.normpath(path)

            # Check if exists
            if os.path.isdir(path):
                self.current_dir = path
                os.chdir(path)
                self._update_prompt()
                self._write_output(f"Changed directory to: {path}\n")
            else:
                self._write_output(f"Directory not found: {path}\n", 'error')

        except Exception as e:
            self._write_output(f"Error changing directory: {e}\n", 'error')

    def _update_prompt(self):
        """Update command prompt."""
        # Shorten path if too long
        display_path = self.current_dir
        if len(display_path) > 40:
            display_path = "..." + display_path[-37:]

        self.prompt_label.config(text=f"{display_path}> ")

    def _history_up(self, event):
        """Navigate command history up."""
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.command_entry.delete(0, END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        return "break"

    def _history_down(self, event):
        """Navigate command history down."""
        if self.command_history and self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index = len(self.command_history)
            self.command_entry.delete(0, END)
        return "break"

    def _autocomplete(self, event):
        """Autocomplete file/directory names."""
        current_text = self.command_entry.get()

        # Get the part to complete
        parts = current_text.split()
        if not parts:
            return "break"

        to_complete = parts[-1]

        # Get directory and prefix
        if '/' in to_complete or '\\' in to_complete:
            dir_path = os.path.dirname(to_complete)
            prefix = os.path.basename(to_complete)
        else:
            dir_path = self.current_dir
            prefix = to_complete

        # Find matches
        try:
            items = os.listdir(dir_path if dir_path else self.current_dir)
            matches = [item for item in items if item.startswith(prefix)]

            if len(matches) == 1:
                # Single match - complete it
                completed = matches[0]
                if dir_path:
                    completed = os.path.join(dir_path, completed)

                # Update entry
                parts[-1] = completed
                self.command_entry.delete(0, END)
                self.command_entry.insert(0, ' '.join(parts))
            elif len(matches) > 1:
                # Multiple matches - show them
                self._write_output(f"\nPossible completions: {', '.join(matches)}\n")
                self._write_output(f"{self.current_dir}> {current_text}")

        except Exception:
            pass

        return "break"

    def execute_command(self, command: str):
        """Execute a command programmatically."""
        self.command_entry.insert(0, command)
        self._execute_command()


class NotesTab(Frame):
    """Note-taking tab for the forensics workbench."""

    def __init__(self, parent, case_dir: str = None):
        """Initialize notes tab.

        Args:
            parent: Parent widget
            case_dir: Case directory path
        """
        super().__init__(parent)

        self.case_dir = case_dir or "."
        self.notes_manager = CaseNotesManager(self.case_dir)
        self.current_note = None

        self._create_widgets()
        self._refresh_notes_list()

    def _create_widgets(self):
        """Create notes tab widgets."""
        # Main paned window
        paned = ttk.PanedWindow(self, orient=HORIZONTAL)
        paned.pack(fill=BOTH, expand=True)

        # Left panel - Notes list
        left_frame = Frame(paned, width=300)
        paned.add(left_frame, weight=1)

        # Notes list header
        header_frame = Frame(left_frame)
        header_frame.pack(fill=X, padx=5, pady=5)

        Label(header_frame, text="Case Notes", font=('Arial', 11, 'bold')).pack(side=LEFT)

        # Add note button
        Button(header_frame, text="+ New Note", command=self._new_note).pack(side=RIGHT)

        # Search box
        search_frame = Frame(left_frame)
        search_frame.pack(fill=X, padx=5, pady=2)

        Label(search_frame, text="Search:").pack(side=LEFT)
        self.search_var = StringVar()
        self.search_var.trace('w', lambda *args: self._filter_notes())
        Entry(search_frame, textvariable=self.search_var).pack(side=LEFT, fill=X, expand=True)

        # Filter options
        filter_frame = Frame(left_frame)
        filter_frame.pack(fill=X, padx=5, pady=2)

        Label(filter_frame, text="Category:").pack(side=LEFT)
        self.category_filter = ttk.Combobox(filter_frame, width=15,
                                            values=["All", "Finding", "Analysis", "Observation", "Evidence",
                                                    "Timeline"])
        self.category_filter.pack(side=LEFT)
        self.category_filter.bind('<<ComboboxSelected>>', lambda e: self._filter_notes())
        self.category_filter.current(0)

        # Notes list
        list_frame = Frame(left_frame)
        list_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)

        scrollbar = Scrollbar(list_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        self.notes_listbox = Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.notes_listbox.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=self.notes_listbox.yview)

        self.notes_listbox.bind('<<ListboxSelect>>', self._on_note_select)

        # Right panel - Note editor
        right_frame = Frame(paned)
        paned.add(right_frame, weight=3)

        # Note details
        details_frame = Frame(right_frame)
        details_frame.pack(fill=X, padx=5, pady=5)

        # Title
        title_frame = Frame(details_frame)
        title_frame.pack(fill=X, pady=2)
        Label(title_frame, text="Title:", width=10, anchor=W).pack(side=LEFT)
        self.title_var = StringVar()
        Entry(title_frame, textvariable=self.title_var).pack(side=LEFT, fill=X, expand=True)

        # Category and Priority
        cat_frame = Frame(details_frame)
        cat_frame.pack(fill=X, pady=2)

        Label(cat_frame, text="Category:", width=10, anchor=W).pack(side=LEFT)
        self.category_var = ttk.Combobox(cat_frame, width=15,
                                         values=["Finding", "Analysis", "Observation", "Evidence", "Timeline"])
        self.category_var.pack(side=LEFT, padx=5)

        Label(cat_frame, text="Priority:").pack(side=LEFT, padx=(20, 5))
        self.priority_var = ttk.Combobox(cat_frame, width=10,
                                         values=["High", "Medium", "Low"])
        self.priority_var.pack(side=LEFT)
        self.priority_var.current(1)

        # Tags
        tags_frame = Frame(details_frame)
        tags_frame.pack(fill=X, pady=2)
        Label(tags_frame, text="Tags:", width=10, anchor=W).pack(side=LEFT)
        self.tags_var = StringVar()
        Entry(tags_frame, textvariable=self.tags_var).pack(side=LEFT, fill=X, expand=True)
        Label(tags_frame, text="(comma separated)", fg='gray').pack(side=LEFT)

        # Evidence references
        evidence_frame = Frame(details_frame)
        evidence_frame.pack(fill=X, pady=2)
        Label(evidence_frame, text="Evidence:", width=10, anchor=W).pack(side=LEFT)
        self.evidence_var = StringVar()
        Entry(evidence_frame, textvariable=self.evidence_var).pack(side=LEFT, fill=X, expand=True)

        # Content editor
        content_frame = Frame(right_frame)
        content_frame.pack(fill=BOTH, expand=True, padx=5, pady=5)

        Label(content_frame, text="Content:", anchor=W).pack(fill=X)

        # Text editor with scrollbar
        text_frame = Frame(content_frame)
        text_frame.pack(fill=BOTH, expand=True)

        text_scrollbar = Scrollbar(text_frame)
        text_scrollbar.pack(side=RIGHT, fill=Y)

        self.content_text = Text(text_frame, wrap=WORD, yscrollcommand=text_scrollbar.set)
        self.content_text.pack(side=LEFT, fill=BOTH, expand=True)
        text_scrollbar.config(command=self.content_text.yview)

        # Formatting toolbar
        toolbar = Frame(content_frame)
        toolbar.pack(fill=X, pady=2)

        Button(toolbar, text="Bold", command=lambda: self._insert_markdown("**")).pack(side=LEFT)
        Button(toolbar, text="Italic", command=lambda: self._insert_markdown("*")).pack(side=LEFT)
        Button(toolbar, text="Code", command=lambda: self._insert_markdown("`")).pack(side=LEFT)
        Button(toolbar, text="List", command=lambda: self._insert_text("- ")).pack(side=LEFT)
        Button(toolbar, text="Link", command=self._insert_link).pack(side=LEFT)
        Button(toolbar, text="Timestamp", command=self._insert_timestamp).pack(side=LEFT)

        # Action buttons
        action_frame = Frame(right_frame)
        action_frame.pack(fill=X, padx=5, pady=5)

        Button(action_frame, text="Save Note", command=self._save_note).pack(side=LEFT, padx=2)
        Button(action_frame, text="Delete Note", command=self._delete_note).pack(side=LEFT, padx=2)
        Button(action_frame, text="Export Notes", command=self._export_notes).pack(side=LEFT, padx=2)
        Button(action_frame, text="Attach File", command=self._attach_file).pack(side=LEFT, padx=2)

        # Status bar
        self.status_label = Label(right_frame, text="Ready", relief=SUNKEN, anchor=W)
        self.status_label.pack(fill=X)

    def _refresh_notes_list(self):
        """Refresh the notes list display."""
        self.notes_listbox.delete(0, END)

        for note in sorted(self.notes_manager.notes,
                           key=lambda n: n.timestamp, reverse=True):
            # Format display text
            display_text = f"[{note.priority[0]}] {note.title}"
            if note.category:
                display_text = f"[{note.category}] {display_text}"

            self.notes_listbox.insert(END, display_text)

            # Color code by priority
            index = self.notes_listbox.size() - 1
            if note.priority == "High":
                self.notes_listbox.itemconfig(index, fg='red')
            elif note.priority == "Low":
                self.notes_listbox.itemconfig(index, fg='gray')

    def _filter_notes(self):
        """Filter displayed notes."""
        query = self.search_var.get()
        category = self.category_filter.get()

        if category == "All":
            category = None

        filtered = self.notes_manager.search_notes(query=query, category=category)

        self.notes_listbox.delete(0, END)
        for note in sorted(filtered, key=lambda n: n.timestamp, reverse=True):
            display_text = f"[{note.priority[0]}] {note.title}"
            if note.category:
                display_text = f"[{note.category}] {display_text}"
            self.notes_listbox.insert(END, display_text)

    def _on_note_select(self, event):
        """Handle note selection."""
        selection = self.notes_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        # Get the note from the filtered/sorted list
        query = self.search_var.get()
        category = self.category_filter.get()
        if category == "All":
            category = None

        filtered = self.notes_manager.search_notes(query=query, category=category)
        sorted_notes = sorted(filtered, key=lambda n: n.timestamp, reverse=True)

        if index < len(sorted_notes):
            self.current_note = sorted_notes[index]
            self._load_note(self.current_note)

    def _load_note(self, note: CaseNote):
        """Load note into editor."""
        self.title_var.set(note.title)
        self.category_var.set(note.category)
        self.priority_var.set(note.priority)
        self.tags_var.set(", ".join(note.tags))
        self.evidence_var.set(", ".join(note.evidence_refs))

        self.content_text.delete('1.0', END)
        self.content_text.insert('1.0', note.content)

        self.status_label.config(
            text=f"Note ID: {note.id} | Created: {note.timestamp.strftime('%Y-%m-%d %H:%M')}"
        )

    def _new_note(self):
        """Create new note."""
        self.current_note = None
        self.title_var.set("New Note")
        self.category_var.set("Observation")
        self.priority_var.set("Medium")
        self.tags_var.set("")
        self.evidence_var.set("")
        self.content_text.delete('1.0', END)
        self.status_label.config(text="Creating new note...")

    def _save_note(self):
        """Save current note."""
        title = self.title_var.get().strip()
        if not title:
            messagebox.showwarning("Invalid Note", "Please enter a title")
            return

        content = self.content_text.get('1.0', END).strip()
        category = self.category_var.get()
        priority = self.priority_var.get()

        # Parse tags and evidence
        tags = [t.strip() for t in self.tags_var.get().split(',') if t.strip()]
        evidence = [e.strip() for e in self.evidence_var.get().split(',') if e.strip()]

        if self.current_note:
            # Update existing
            self.notes_manager.update_note(
                self.current_note.id,
                title=title,
                content=content,
                category=category,
                priority=priority,
                tags=tags,
                evidence_refs=evidence
            )
            self.status_label.config(text=f"Note updated: {self.current_note.id}")
        else:
            # Create new
            note = self.notes_manager.add_note(
                title=title,
                content=content,
                category=category,
                priority=priority,
                tags=tags,
                evidence_refs=evidence
            )
            self.current_note = note
            self.status_label.config(text=f"Note created: {note.id}")

        self._refresh_notes_list()

    def _delete_note(self):
        """Delete current note."""
        if not self.current_note:
            return

        if messagebox.askyesno("Delete Note",
                               f"Delete note '{self.current_note.title}'?"):
            self.notes_manager.delete_note(self.current_note.id)
            self._new_note()
            self._refresh_notes_list()
            self.status_label.config(text="Note deleted")

    def _export_notes(self):
        """Export notes to file."""
        format_dialog = Toplevel(self)
        format_dialog.title("Export Notes")
        format_dialog.geometry("300x150")

        Label(format_dialog, text="Select export format:").pack(pady=10)

        format_var = StringVar(value="markdown")
        formats = [("Markdown", "markdown"), ("HTML", "html"), ("JSON", "json")]

        for text, value in formats:
            Radiobutton(format_dialog, text=text, variable=format_var,
                        value=value).pack(anchor=W, padx=20)

        def do_export():
            fmt = format_var.get()
            ext = {"markdown": ".md", "html": ".html", "json": ".json"}[fmt]

            filename = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")]
            )

            if filename:
                content = self.notes_manager.export_notes(fmt, filename)
                messagebox.showinfo("Export Complete", f"Notes exported to {filename}")
                format_dialog.destroy()

        Button(format_dialog, text="Export", command=do_export).pack(pady=10)

    def _attach_file(self):
        """Attach file to note."""
        if not self.current_note:
            messagebox.showwarning("No Note", "Please select or create a note first")
            return

        filename = filedialog.askopenfilename()
        if filename:
            # Copy file to case directory
            attachments_dir = Path(self.case_dir) / "notes" / "attachments"
            attachments_dir.mkdir(parents=True, exist_ok=True)

            dest = attachments_dir / os.path.basename(filename)
            shutil.copy2(filename, dest)

            # Add to note
            if self.current_note.attachments is None:
                self.current_note.attachments = []
            self.current_note.attachments.append(str(dest))

            # Save
            self.notes_manager.update_note(
                self.current_note.id,
                attachments=self.current_note.attachments
            )

            self.status_label.config(text=f"File attached: {os.path.basename(filename)}")

    def _insert_markdown(self, marker):
        """Insert markdown formatting."""
        try:
            sel_start = self.content_text.index(SEL_FIRST)
            sel_end = self.content_text.index(SEL_LAST)
            selected = self.content_text.get(sel_start, sel_end)

            self.content_text.delete(sel_start, sel_end)
            self.content_text.insert(sel_start, f"{marker}{selected}{marker}")
        except:
            # No selection
            pos = self.content_text.index(INSERT)
            self.content_text.insert(pos, marker * 2)
            # Move cursor between markers
            self.content_text.mark_set(INSERT, f"{pos}+{len(marker)}c")

    def _insert_text(self, text):
        """Insert text at cursor."""
        self.content_text.insert(INSERT, text)

    def _insert_link(self):
        """Insert markdown link."""
        try:
            selected = self.content_text.get(SEL_FIRST, SEL_LAST)
            self.content_text.delete(SEL_FIRST, SEL_LAST)
            self.content_text.insert(SEL_FIRST, f"[{selected}](url)")
        except:
            self.content_text.insert(INSERT, "[text](url)")

    def _insert_timestamp(self):
        """Insert current timestamp."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.content_text.insert(INSERT, f"\n[{timestamp}] ")

    def add_finding(self, title: str, content: str, evidence: str = None):
        """Add a finding note programmatically."""
        note = self.notes_manager.add_note(
            title=title,
            content=content,
            category="Finding",
            priority="High",
            evidence_refs=[evidence] if evidence else []
        )
        self._refresh_notes_list()
        return note