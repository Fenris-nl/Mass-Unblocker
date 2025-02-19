import os
import datetime
import logging
import threading
import tkinter as tk
import tkinter.filedialog as filedialog
import tkinter.messagebox as messagebox
import csv
import json
from PIL import Image, ImageTk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import traceback
from typing import List, Tuple, Optional, Callable

# Enhanced logging: log to file and stream.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Decorator to catch exceptions in background (GUI) threads.


def gui_thread(func):
    def wrapper(*args, **kwargs):
        def task():
            try:
                func(*args, **kwargs)
            except Exception as e:
                logging.error(f"GUI Error: {traceback.format_exc()}")
                args[0].after(0, lambda: messagebox.showerror(
                    "Critical Error", f"Application error:\n{str(e)}"))
        threading.Thread(target=task, daemon=True).start()
    return wrapper

# Progress dialog with cancel support.


class ProgressDialog(ttk.Toplevel):
    def __init__(self, parent, title="Processing"):
        super().__init__(parent)
        self.title(title)
        self.geometry("300x100")
        self.progress = ttk.Progressbar(
            self, mode="indeterminate", bootstyle=SUCCESS)
        self.progress.pack(padx=20, pady=20, fill="x")
        self.cancel_button = ttk.Button(
            self, text="Cancel", command=self.cancel, bootstyle=WARNING)
        self.cancel_button.pack(pady=10)
        self.cancelled = False
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def cancel(self):
        self.cancelled = True
        self.destroy()

# Simple history manager & unblock action (undo not fully implemented).


class HistoryManager:
    def __init__(self):
        self._undo_stack = []
        self._redo_stack = []

    def add_action(self, action):
        self._undo_stack.append(action)
        self._redo_stack.clear()

    def undo(self):
        if self._undo_stack:
            action = self._undo_stack.pop()
            action.undo()
            self._redo_stack.append(action)

    def redo(self):
        if self._redo_stack:
            action = self._redo_stack.pop()
            action.execute()
            self._undo_stack.append(action)


class UnblockAction:
    def __init__(self, app, files: List[str]):
        self.app = app
        self.files = files

    def execute(self):
        for file_path in self.files:
            unblock_file(file_path)

    def undo(self):
        # Re-blocking is not implemented; log the action.
        logging.info("Undo is not implemented for unblocking actions.")

# Minimal virtual tree view to support large datasets.


class VirtualTreeView(ttk.Treeview):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._data = []

    def set_data(self, data: List[Tuple]):
        self._data = data
        self.refresh()

    def refresh(self):
        self.delete(*self.get_children())
        # For simplicity, load all items if <1000; otherwise, load first 100.
        items = self._data if len(self._data) < 1000 else self._data[:100]
        for item in items:
            self.insert("", "end", values=item)

# Functions for file blocking/unblocking.


def is_file_blocked(file_path: str) -> bool:
    try:
        with open(file_path + ":Zone.Identifier", 'r'):
            return True
    except FileNotFoundError:
        return False
    except Exception as e:
        logging.error(
            f"Error checking block status for {file_path}: {traceback.format_exc()}")
        return False


def unblock_file(file_path: str) -> bool:
    try:
        os.remove(file_path + ":Zone.Identifier")
        logging.info(f"Unblocked file: {file_path}")
        return True
    except Exception as e:
        logging.error(
            f"Error unblocking file {file_path}: {traceback.format_exc()}")
        return False

# Scans directories for .exe files and collects additional details.


class FileScanner:
    def __init__(self, directory: str):
        self.directory: str = directory
        # Each record: (File Path, Size, Modified, Status, Tag)
        self.file_records: List[Tuple[str, str, str, str, str]] = []
        self.stop_scanning: bool = False

    def scan(self, progress_callback: Optional[Callable[[str], None]] = None) -> None:
        try:
            total_exe = sum(1 for root, _, files in os.walk(self.directory)
                            for file in files if file.lower().endswith(".exe"))
            if total_exe == 0:
                total_exe = 1
            processed = 0
            blocked_count = 0
            unblocked_count = 0
            records = []
            for root, _, files in os.walk(self.directory):
                for file in files:
                    if self.stop_scanning:
                        logging.info("Scanning cancelled by user.")
                        if progress_callback:
                            progress_callback("Scan cancelled.")
                        self.file_records = records
                        return
                    if file.lower().endswith(".exe"):
                        processed += 1
                        full_path = os.path.join(root, file)
                        try:
                            stats = os.stat(full_path)
                            size = f"{stats.st_size/1024:.2f} KB"
                            modified = datetime.datetime.fromtimestamp(
                                stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception as e:
                            size = "N/A"
                            modified = "N/A"
                        if is_file_blocked(full_path):
                            blocked_count += 1
                            status_text = "Blocked"
                            tag = "blocked"
                        else:
                            unblocked_count += 1
                            status_text = "Unblocked"
                            tag = "unblocked"
                        records.append(
                            (full_path, size, modified, status_text, tag))
                        if progress_callback:
                            progress_callback(str(processed / total_exe * 100))
            self.file_records = records
            summary = f"Found {len(records)} executables: {blocked_count} blocked, {unblocked_count} unblocked."
            if progress_callback:
                progress_callback(summary)
            logging.info(summary)
        except PermissionError as pe:
            logging.error(f"Permission denied: {pe}")
            if progress_callback:
                progress_callback("Permission denied during scan.")
        except Exception as e:
            logging.error(
                f"Error scanning directory {self.directory}: {traceback.format_exc()}")
            if progress_callback:
                progress_callback("Error scanning directory.")

# Main application class.


class UnblockerApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="cyborg")
        self.title("Executable Unblocker - Program Center")
        self.geometry("1280x800")
        self.minsize(1024, 600)
        self.resizable(True, True)

        self.title_font = ("Segoe UI", 14, "bold")
        self.base_font = ("Segoe UI", 10)
        self.detail_font = ("Consolas", 9)
        self._setup_icons()

        # List of file records: (File, Size, Modified, Status, Tag)
        self.file_records: List[Tuple[str, str, str, str, str]] = []
        self.current_view: str = "list"  # "list" or "icon"
        self._sort_directions = {"File": True,
                                 "Size": True, "Modified": True, "Status": True}
        self.icon_selected = {}  # {full_path: bool}
        self.icon_buttons = {}   # {full_path: ttk.Button}
        self.history_manager = HistoryManager()
        self.max_scan_time = 120

        self._create_menubar()
        self._create_top_toolbar()
        self._create_search_bar()
        self._create_shortcuts_panel()
        self._create_main_content()
        self._create_status_bar()
        self._setup_treeview()
        self._setup_icon_view()
        self._setup_context_menu()
        self._setup_icon_context_menu()

        self.tree_frame.pack(fill="both", expand=True)

        # Keyboard shortcuts.
        self.bind("<F5>", lambda e: self.refresh_list_async())
        self.bind("<Control-a>", lambda e: self.select_all())
        self.bind("<Control-d>", lambda e: self.deselect_all())

        # Set initial directory.
        self.current_directory = os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Apps")
        if not os.path.exists(self.current_directory):
            self.current_directory = os.path.expanduser("~")
        self.refresh_list_async()

    @property
    def current_directory(self) -> str:
        return self.dir_entry.get()

    @current_directory.setter
    def current_directory(self, value: str):
        self.dir_entry.delete(0, tk.END)
        self.dir_entry.insert(0, value)

    def _setup_icons(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        icon_size = (64, 64)
        blocked_path = os.path.join(script_dir, "blocked.png")
        unblocked_path = os.path.join(script_dir, "unblocked.png")
        try:
            blocked_img = Image.open(blocked_path).resize(
                icon_size, Image.LANCZOS)
            unblocked_img = Image.open(unblocked_path).resize(
                icon_size, Image.LANCZOS)
        except Exception as e:
            logging.error(f"Error loading images: {e}")
            blocked_img = Image.new("RGB", icon_size, color="red")
            unblocked_img = Image.new("RGB", icon_size, color="green")
        self._blocked_icon = ImageTk.PhotoImage(blocked_img)
        self._unblocked_icon = ImageTk.PhotoImage(unblocked_img)

    def _create_menubar(self):
        self.menubar = ttk.Menu(self)
        file_menu = ttk.Menu(self.menubar, tearoff=False)
        file_menu.add_command(label="Select Directory",
                              command=self.browse_directory)
        file_menu.add_command(label="Refresh List",
                              command=self.refresh_list_async)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        self.menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = ttk.Menu(self.menubar, tearoff=False)
        edit_menu.add_command(label="Undo", command=self.history_manager.undo)
        edit_menu.add_command(label="Redo", command=self.history_manager.redo)
        self.menubar.add_cascade(label="Edit", menu=edit_menu)

        theme_menu = ttk.Menu(self.menubar, tearoff=False)
        for theme in self.style.theme_names():
            theme_menu.add_command(
                label=theme, command=lambda t=theme: self.style.theme_use(t))
        self.menubar.add_cascade(label="Themes", menu=theme_menu)

        export_menu = ttk.Menu(self.menubar, tearoff=False)
        export_menu.add_command(label="Export to CSV", command=self.export_csv)
        export_menu.add_command(label="Export to JSON",
                                command=self.export_json)
        self.menubar.add_cascade(label="Export", menu=export_menu)

        help_menu = ttk.Menu(self.menubar, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=self.menubar)

    def _create_top_toolbar(self):
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(side="top", fill="x")
        ttk.Label(top_frame, text="Directory:",
                  font=self.base_font).pack(side="left", padx=5)
        self.dir_entry = ttk.Entry(top_frame, width=80, font=self.base_font)
        self.dir_entry.pack(side="left", padx=5)
        browse_btn = ttk.Button(top_frame, text="Browse",
                                command=self.browse_directory, bootstyle=PRIMARY)
        browse_btn.pack(side="left", padx=5)
        ToolTip(browse_btn, text="Select a directory",
                bootstyle=(INFO, INVERSE))
        toolbar = ttk.Frame(self, padding=5)
        toolbar.pack(side="top", fill="x")
        btn_refresh = ttk.Button(
            toolbar, text="⟳ Refresh List", command=self.refresh_list_async, bootstyle=SUCCESS)
        btn_refresh.pack(side="left", padx=5)
        ToolTip(btn_refresh, text="Refresh the file list",
                bootstyle=(INFO, INVERSE))
        btn_select_all = ttk.Button(
            toolbar, text="✓ Select All", command=self.select_all, bootstyle=INFO)
        btn_select_all.pack(side="left", padx=5)
        ToolTip(btn_select_all, text="Select all files",
                bootstyle=(INFO, INVERSE))
        btn_deselect_all = ttk.Button(
            toolbar, text="✗ Deselect All", command=self.deselect_all, bootstyle=INFO)
        btn_deselect_all.pack(side="left", padx=5)
        ToolTip(btn_deselect_all, text="Deselect all files",
                bootstyle=(INFO, INVERSE))
        btn_unblock_selected = ttk.Button(
            toolbar, text="🛡️ Unblock Selected", command=self.unblock_selected, bootstyle=WARNING)
        btn_unblock_selected.pack(side="left", padx=5)
        ToolTip(btn_unblock_selected, text="Unblock selected files",
                bootstyle=(INFO, INVERSE))
        btn_unblock_all = ttk.Button(
            toolbar, text="⚠️ Unblock All", command=self.confirm_unblock_all, bootstyle=DANGER)
        btn_unblock_all.pack(side="left", padx=5)
        ToolTip(btn_unblock_all, text="Unblock all blocked files",
                bootstyle=(INFO, INVERSE))
        btn_toggle_view = ttk.Button(
            toolbar, text="⇄ Toggle View", command=self.toggle_view, bootstyle=SECONDARY)
        btn_toggle_view.pack(side="left", padx=5)
        ToolTip(btn_toggle_view, text="Switch between list and icon views",
                bootstyle=(INFO, INVERSE))
        btn_cancel_scan = ttk.Button(
            toolbar, text="Cancel Scan", command=self.cancel_scan, bootstyle=DANGER)
        btn_cancel_scan.pack(side="left", padx=5)
        ToolTip(btn_cancel_scan, text="Cancel current scan",
                bootstyle=(INFO, INVERSE))

    def _create_search_bar(self):
        search_frame = ttk.Frame(self, padding=5)
        search_frame.pack(side="top", fill="x")
        ttk.Label(search_frame, text="Filter:",
                  font=self.base_font).pack(side="left", padx=5)
        self.filter_var = ttk.StringVar()
        self.filter_entry = ttk.Entry(
            search_frame, textvariable=self.filter_var, font=self.base_font, width=40, foreground="#666")
        self.filter_entry.pack(side="left", padx=5)
        self.filter_entry.insert(0, "Filter by filename...")
        self.filter_entry.bind("<FocusIn>", self._clear_filter_placeholder)
        self.filter_entry.bind("<FocusOut>", self._restore_filter_placeholder)
        btn_apply_filter = ttk.Button(
            search_frame, text="Apply Filter", command=self.apply_filter, bootstyle=PRIMARY)
        btn_apply_filter.pack(side="left", padx=5)
        ToolTip(btn_apply_filter, text="Apply the current filter",
                bootstyle=(INFO, INVERSE))
        btn_clear_filter = ttk.Button(
            search_frame, text="Clear Filter", command=self.clear_filter, bootstyle=SECONDARY)
        btn_clear_filter.pack(side="left", padx=5)
        ToolTip(btn_clear_filter, text="Clear the filter",
                bootstyle=(INFO, INVERSE))

    def _create_shortcuts_panel(self):
        self.shortcuts_frame = ttk.Frame(self, padding=5)
        self.shortcuts_frame.pack(side="top", fill="x")
        shortcuts_text = (
            "Keyboard Shortcuts:\n"
            "   F5       - Refresh List\n"
            "   Ctrl+A   - Select All\n"
            "   Ctrl+D   - Deselect All\n"
            "   Arrow Keys - Navigate List\n"
            "   Right-Click on Tree or Icon - Show Context Menu"
        )
        self.shortcuts_label = ttk.Label(
            self.shortcuts_frame, text=shortcuts_text, font=self.base_font)
        self.shortcuts_label.pack(side="left", padx=5)

    def _create_main_content(self):
        self.paned = ttk.PanedWindow(self, orient="horizontal")
        self.paned.pack(fill="both", expand=True, padx=10, pady=10)
        self.left_container = ttk.Frame(self.paned)
        self.paned.add(self.left_container, weight=3)
        self.details_frame = ttk.Frame(self.paned, padding=10)
        self.paned.add(self.details_frame, weight=1)
        ttk.Label(self.details_frame, text="File Details",
                  font=self.title_font, bootstyle=PRIMARY).pack(anchor="nw", pady=5)
        self.details_text = ttk.Text(self.details_frame, wrap="word",
                                     font=self.detail_font, state="disabled", height=15, width=40)
        self.details_text.pack(anchor="nw", pady=10)

    def _create_status_bar(self):
        status_frame = ttk.Frame(self, padding=5)
        status_frame.pack(side="bottom", fill="x")
        self.status_left = ttk.Label(
            status_frame, text="Ready", anchor="w", font=("Segoe UI", 9))
        self.status_left.pack(side="left", fill="x", expand=True)
        self.status_right = ttk.Label(
            status_frame, text="", anchor="e", font=("Segoe UI", 9))
        self.status_right.pack(side="right")
        self.stats = {
            'total': ttk.Label(status_frame, text="Total: 0"),
            'blocked': ttk.Label(status_frame, text="Blocked: 0", bootstyle=DANGER),
            'selected': ttk.Label(status_frame, text="Selected: 0", bootstyle=INFO)
        }
        for lbl in self.stats.values():
            lbl.pack(side="right", padx=10)
        self.progress = ttk.Progressbar(
            status_frame, mode="indeterminate", length=200, bootstyle=SUCCESS)
        self.progress.pack(side="right", padx=5)

    def _setup_treeview(self):
        self.tree_frame = ttk.Frame(self.left_container)
        self.tree = VirtualTreeView(
            self.tree_frame,
            columns=("File", "Size", "Modified", "Status"),
            show="headings",
            selectmode="extended",
            height=15
        )
        self.tree.heading("File", text="File Path",
                          command=lambda: self.sort_column("File"))
        self.tree.heading("Size", text="Size",
                          command=lambda: self.sort_column("Size"))
        self.tree.heading("Modified", text="Modified",
                          command=lambda: self.sort_column("Modified"))
        self.tree.heading("Status", text="Status",
                          command=lambda: self.sort_column("Status"))
        self.tree.column("File", width=600, anchor="w")
        self.tree.column("Size", width=100, anchor="e")
        self.tree.column("Modified", width=150, anchor="w")
        self.tree.column("Status", width=100, anchor="center")
        self.tree_scroll = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.tag_configure(
            "blocked", background="#fee", foreground="#d00")
        self.tree.tag_configure(
            "unblocked", background="#efe", foreground="#090")
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.update_details())
        self.tree.bind("<Button-3>", self.show_context_menu)

    # ----- Modified Icon View Setup with Dynamic Arrangement -----
    def _setup_icon_view(self):
        self.icon_frame = ttk.Frame(self.left_container)
        self.icon_canvas = ttk.Canvas(self.icon_frame)
        self.icon_scroll = ttk.Scrollbar(
            self.icon_frame, orient="vertical", command=self.icon_canvas.yview)
        self.icon_canvas.configure(yscrollcommand=self.icon_scroll.set)
        self.icon_scroll.pack(side="right", fill="y")
        self.icon_canvas.pack(side="left", fill="both", expand=True)
        self.icon_inner = ttk.Frame(self.icon_canvas)
        self.icon_canvas.create_window(
            (0, 0), window=self.icon_inner, anchor="nw")
        self.icon_inner.bind("<Configure>", self.handle_icon_inner_configure)
        self.last_icon_inner_width = 0  # Track the last known width for resize detection

    def handle_icon_inner_configure(self, event):
        """Handle resize events for the icon view container."""
        self.icon_canvas.configure(scrollregion=self.icon_canvas.bbox("all"))
        current_width = self.icon_inner.winfo_width()
        if abs(current_width - self.last_icon_inner_width) > 10:  # Prevent minor resize flickering
            self.arrange_icons()
            self.last_icon_inner_width = current_width

    def populate_icon_view(self, records: List[Tuple[str, str, str, str, str]]):
        """Create icon buttons but don't arrange them yet."""
        for widget in self.icon_inner.winfo_children():
            widget.destroy()
        self.icon_buttons.clear()

        for record in records:
            full_path, _, _, status_text, tag = record
            selected = self.icon_selected.get(full_path, False)
            base_name = os.path.basename(full_path)
            btn_text = f"✔ {base_name}" if selected else base_name
            btn = ttk.Button(
                self.icon_inner,
                image=(self._blocked_icon if status_text ==
                       "Blocked" else self._unblocked_icon),
                text=btn_text,
                compound="top",
                width=12,
                command=lambda fp=full_path: self.toggle_icon_selection(fp)
            )
            btn.configure(bootstyle="primary" if selected else (
                DANGER if status_text == "Blocked" else SUCCESS))
            self.icon_buttons[full_path] = btn
            ToolTip(btn, text=full_path, bootstyle=(INFO, INVERSE))
            btn.bind("<Button-3>", lambda event,
                     fp=full_path: self.show_icon_context_menu(event, fp))

        self.arrange_icons()  # Initial arrangement

    def arrange_icons(self):
        """Dynamically arrange icons based on current container width."""
        container_width = self.icon_inner.winfo_width()
        icon_width = 170  # Adjusted for button width + padding (150 + 20)
        columns = max(1, container_width //
                      icon_width) if container_width > 0 else 4

        # Re-grid all buttons
        for idx, (full_path, btn) in enumerate(self.icon_buttons.items()):
            row = idx // columns
            col = idx % columns
            btn.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

        # Configure columns to expand
        for col in range(columns):
            self.icon_inner.columnconfigure(col, weight=1)
    # ----- End of Modified Icon View Setup -----

    def _setup_context_menu(self):
        self.context_menu = ttk.Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Open Containing Folder", command=self.open_containing_folder)
        self.context_menu.add_command(
            label="Copy File Path", command=self.copy_file_path)

    def _setup_icon_context_menu(self):
        self.icon_context_menu = ttk.Menu(self, tearoff=0)
        self.icon_context_menu.add_command(
            label="Open Containing Folder", command=lambda: self.open_icon_containing_folder(self.context_icon_file))
        self.icon_context_menu.add_command(
            label="Copy File Path", command=lambda: self.copy_icon_file_path(self.context_icon_file))

    def show_icon_context_menu(self, event, file_path):
        self.context_icon_file = file_path
        self.icon_context_menu.post(event.x_root, event.y_root)

    def open_icon_containing_folder(self, file_path):
        folder = os.path.dirname(file_path)
        try:
            os.startfile(folder)
        except Exception as e:
            messagebox.showerror(
                "Error", f"Unable to open folder:\n{folder}\n{e}")

    def copy_icon_file_path(self, file_path):
        self.clipboard_clear()
        self.clipboard_append(file_path)
        messagebox.showinfo("Copied", "File path copied to clipboard.")

    def _clear_filter_placeholder(self, event):
        if self.filter_entry.get() == "Filter by filename...":
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.configure(foreground="black")

    def _restore_filter_placeholder(self, event):
        if not self.filter_entry.get():
            self.filter_entry.insert(0, "Filter by filename...")
            self.filter_entry.configure(foreground="#666")

    def browse_directory(self):
        selected_dir = filedialog.askdirectory(
            initialdir=self.current_directory)
        if selected_dir:
            self.current_directory = selected_dir
            self.refresh_list_async()

    def cancel_scan(self):
        self.scanner.stop_scanning = True

    def update_status(self, msg: str):
        self.after(0, lambda: self.status_left.config(text=msg))

    def update_progress(self, value):
        self.after(0, lambda: self.progress.config(value=value))

    def refresh_list_async(self):
        self.scan_start_time = datetime.datetime.now()
        self.status_left.config(text="Scanning directory...")
        self.progress.config(mode="determinate", maximum=100, value=0)
        self.file_records = []
        self.tree.delete(*self.tree.get_children())
        for widget in self.icon_inner.winfo_children():
            widget.destroy()
        self.icon_buttons.clear()
        self.scanner = FileScanner(self.current_directory)
        self.scanner.stop_scanning = False

        def progress_callback(msg):
            try:
                percentage = float(msg)
                self.update_progress(percentage)
                self.update_status(f"Scanning... {percentage:.0f}% complete")
            except:
                self.update_status(msg)

        scan_thread = threading.Thread(
            target=lambda: self.scanner.scan(progress_callback=progress_callback))
        scan_thread.daemon = True
        scan_thread.start()
        self.after(500, lambda: self._check_scan_complete(
            self.scanner, scan_thread))

    def _check_scan_complete(self, scanner, thread):
        elapsed = (datetime.datetime.now() -
                   self.scan_start_time).total_seconds()
        self.populate_treeview(scanner.file_records)
        if elapsed > self.max_scan_time:
            scanner.stop_scanning = True
            self.progress.stop()
            self.status_left.config(text="Scan timed out.")
            return
        if thread.is_alive():
            self.after(500, lambda: self._check_scan_complete(scanner, thread))
        else:
            self.file_records = scanner.file_records
            self.apply_filter()
            self.progress.config(value=100)
            total = len(self.file_records)
            blocked = sum(
                1 for rec in self.file_records if rec[3] == "Blocked")
            self.stats['total'].config(text=f"Total: {total}")
            self.stats['blocked'].config(text=f"Blocked: {blocked}")

    def populate_treeview(self, records: List[Tuple[str, str, str, str, str]]):
        def _populate():
            self.tree.set_data([(rec[0], rec[1], rec[2], rec[3])
                               for rec in records])
        self.after(0, _populate)

    def apply_filter(self):
        filter_text = self.filter_var.get().lower().strip()
        if filter_text and filter_text != "filter by filename...":
            filtered = [
                rec for rec in self.file_records if filter_text in rec[0].lower()]
        else:
            filtered = self.file_records[:]
        if self.current_view == "list":
            self.populate_treeview(filtered)
        else:
            self.populate_icon_view(filtered)
        selected_count = sum(
            1 for rec in filtered if self.icon_selected.get(rec[0], False))
        self.stats['selected'].config(text=f"Selected: {selected_count}")

    def clear_filter(self):
        self.filter_var.set("")
        self.apply_filter()

    def toggle_view(self):
        if self.current_view == "list":
            self.current_view = "icon"
            self.tree_frame.pack_forget()
            self.icon_frame.pack(fill="both", expand=True)
            self.apply_filter()
        else:
            self.current_view = "list"
            self.icon_frame.pack_forget()
            self.tree_frame.pack(fill="both", expand=True)
            self.apply_filter()

    def sort_column(self, col: str):
        if self.current_view != "list":
            messagebox.showinfo("Info", "Sorting not available in icon view.")
            return
        children = self.tree.get_children("")
        data = []
        for child in children:
            values = self.tree.item(child, "values")
            if col == "File":
                key = values[0]
            elif col == "Size":
                try:
                    key = float(values[1].split()[0])
                except:
                    key = 0
            elif col == "Modified":
                key = values[2]
            elif col == "Status":
                key = values[3]
            else:
                key = values[0]
            data.append((key, child))
        ascending = self._sort_directions.get(col, True)
        data.sort(reverse=not ascending, key=lambda x: x[0])
        for index, (_, child) in enumerate(data):
            self.tree.move(child, '', index)
        self._sort_directions[col] = not ascending

    def update_details(self):
        selected = self.tree.selection()
        if not selected:
            self.details_text.config(state="normal")
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, "No file selected.")
            self.details_text.config(state="disabled")
            return
        item = selected[0]
        values = self.tree.item(item, "values")
        full_path = values[0]
        status = values[3]
        self.show_file_details(full_path, status)

    def show_file_details(self, full_path: str, status: str):
        try:
            stats = os.stat(full_path)
            size = f"{stats.st_size/1024:.2f} KB"
            mtime = datetime.datetime.fromtimestamp(
                stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            logging.error(f"Error getting details for {full_path}: {e}")
            size = "N/A"
            mtime = "N/A"
        details = (
            f"File Path: {full_path}\n"
            f"Size: {size}\n"
            f"Last Modified: {mtime}\n"
            f"Status: {status}\n" +
            ("Zone.Identifier: Present\n" if status ==
             "Blocked" else "Zone.Identifier: Not Present\n")
        )
        self.details_text.config(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details)
        self.details_text.config(state="disabled")

    def show_context_menu(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            row_id = self.tree.identify_row(event.y)
            if row_id not in self.tree.selection():
                self.tree.selection_set(row_id)
            self.context_menu.post(event.x_root, event.y_root)

    def open_containing_folder(self):
        selected = self.tree.selection()
        if not selected:
            return
        full_path = self.tree.item(selected[0], "values")[0]
        folder = os.path.dirname(full_path)
        try:
            os.startfile(folder)
        except Exception as e:
            messagebox.showerror(
                "Error", f"Unable to open folder:\n{folder}\n{e}")

    def copy_file_path(self):
        selected = self.tree.selection()
        if not selected:
            return
        full_path = self.tree.item(selected[0], "values")[0]
        self.clipboard_clear()
        self.clipboard_append(full_path)
        messagebox.showinfo("Copied", "File path copied to clipboard.")

    @gui_thread
    def unblock_selected(self):
        files_to_unblock = []
        if self.current_view == "list":
            selected_items = self.tree.selection()
            if not selected_items:
                messagebox.showinfo("Info", "No files selected!")
                return
            for item in selected_items:
                full_path, _, _, status = self.tree.item(item, "values")
                if status == "Blocked":
                    files_to_unblock.append(full_path)
        else:
            for fp, selected in self.icon_selected.items():
                if selected and is_file_blocked(fp):
                    files_to_unblock.append(fp)
        if not files_to_unblock:
            messagebox.showinfo("Info", "No blocked files selected!")
            return
        self._unblock_files(files_to_unblock)
        action = UnblockAction(self, files_to_unblock)
        self.history_manager.add_action(action)
        self.refresh_list_async()

    @gui_thread
    def _unblock_files(self, files: List[str]):
        dialog = ProgressDialog(self, "Unblocking Files")
        dialog.progress.start(10)
        for file_path in files:
            if dialog.cancelled:
                break
            success = unblock_file(file_path)
            self.after(0, lambda fp=file_path,
                       s=success: self._update_unblock_status(fp, s))
        dialog.progress.stop()
        dialog.destroy()
        self.after(0, lambda: messagebox.showinfo(
            "Done", "Processing completed."))

    def _update_unblock_status(self, file_path: str, success: bool):
        if self.current_view == "list":
            for child in self.tree.get_children():
                values = self.tree.item(child, "values")
                if values[0] == file_path:
                    new_status = "Unblocked" if success else "Blocked"
                    new_tag = "unblocked" if success else "blocked"
                    self.tree.item(child, values=(
                        file_path, values[1], values[2], new_status), tags=(new_tag,))
                    break
        elif self.current_view == "icon":
            btn = self.icon_buttons.get(file_path)
            if btn:
                base_name = os.path.basename(file_path)
                btn.configure(text=base_name)
        if self.details_text.get("1.0", tk.END).find(file_path) != -1:
            self.show_file_details(
                file_path, "Unblocked" if success else "Blocked")

    def confirm_unblock_all(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to unblock all files?"):
            self.unblock_all()

    @gui_thread
    def unblock_all(self):
        files_to_unblock = [full_path for (
            full_path, _, _, status, _) in self.file_records if status == "Blocked"]
        if not files_to_unblock:
            messagebox.showinfo("Info", "No blocked files found!")
            return
        self._unblock_files(files_to_unblock)
        action = UnblockAction(self, files_to_unblock)
        self.history_manager.add_action(action)
        self.refresh_list_async()

    def select_all(self):
        if self.current_view == "list":
            self.tree.selection_set(self.tree.get_children())
        else:
            for fp, btn in self.icon_buttons.items():
                self.icon_selected[fp] = True
                base_name = os.path.basename(fp)
                btn.configure(text=f"✔ {base_name}", bootstyle="primary")
        self.apply_filter()

    def deselect_all(self):
        if self.current_view == "list":
            self.tree.selection_remove(self.tree.selection())
        else:
            for fp, btn in self.icon_buttons.items():
                self.icon_selected[fp] = False
                base_name = os.path.basename(fp)
                btn.configure(
                    text=base_name, bootstyle=DANGER if is_file_blocked(fp) else SUCCESS)
        self.apply_filter()

    def show_about(self):
        about_text = (
            "Executable Unblocker - Program Center\n"
            "Version: 1.0.0\n\n"
            "A tool to scan and unblock executables.\n\n"
            "Developed by: Kaan Erdem\n"
            "Email: kaanerdem3@gmail.com\n"
            "GitHub: https://github.com/Fenris-nl\n\n"
            "Thank you for using this application!"
        )
        messagebox.showinfo("About", about_text)

    def export_csv(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(
                        ["File Path", "Size", "Modified", "Status"])
                    for rec in self.file_records:
                        writer.writerow([rec[0], rec[1], rec[2], rec[3]])
                messagebox.showinfo("Export", "Data exported successfully.")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def export_json(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if filename:
            try:
                data = [{"File Path": rec[0], "Size": rec[1], "Modified": rec[2],
                         "Status": rec[3]} for rec in self.file_records]
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4)
                messagebox.showinfo("Export", "Data exported successfully.")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))


if __name__ == "__main__":
    app = UnblockerApp()
    app.mainloop()
