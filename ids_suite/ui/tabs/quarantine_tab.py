"""
ClamAV Quarantine Tab - Extracted from main_window.py
Manages quarantined files with restore and delete operations
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import json
import subprocess
from datetime import datetime
from typing import Dict, Any

from ids_suite.ui.tabs.base_tab import BaseTab
from ids_suite.ui.components.treeview_builder import TreeviewBuilder
from ids_suite.core.validators import validate_file_path


class QuarantineTab(BaseTab):
    """
    ClamAV Quarantine management tab.

    Features:
    - View quarantined files with metadata
    - Delete individual files or clean all
    - Restore files to original location
    - Sort by date, filename, size, or path
    - Context menu for quick actions
    """

    def __init__(self, parent, app):
        """
        Initialize quarantine tab.

        Args:
            parent: Parent widget (notebook)
            app: SecurityControlPanel instance
        """
        # Initialize sort state before calling super().__init__
        self.quarantine_sort_column = 'date'
        self.quarantine_sort_reverse = True
        self.quarantine_data: Dict[str, Dict[str, Any]] = {}

        # Storage for UI elements
        self.quarantine_tree = None
        self.quarantine_delete_btn = None
        self.quarantine_restore_btn = None

        super().__init__(parent, app)

    def _create_widgets(self) -> None:
        """Create quarantine tab UI components"""
        # Header with actions
        header_frame = ttk.Frame(self.frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="Quarantined Files",
            style='Title.TLabel'
        ).pack(side=tk.LEFT)

        # Action buttons
        factory = self.get_widget_factory()

        factory.create_button(
            header_frame,
            text="󰑐 Refresh",
            command=self.refresh
        ).pack(side=tk.RIGHT, padx=5)

        factory.create_button(
            header_frame,
            text="󰃢 Clean All",
            command=self._on_clean_all
        ).pack(side=tk.RIGHT, padx=5)

        self.quarantine_delete_btn = factory.create_button(
            header_frame,
            text="󰆴 Delete Selected",
            command=self._on_delete_selected
        )
        self.quarantine_delete_btn.pack(side=tk.RIGHT, padx=5)
        self._create_tooltip(
            self.quarantine_delete_btn,
            "Permanently delete selected file"
        )

        self.quarantine_restore_btn = factory.create_button(
            header_frame,
            text="󰁯 Restore Selected",
            command=self._on_restore_selected
        )
        self.quarantine_restore_btn.pack(side=tk.RIGHT, padx=5)
        self._create_tooltip(
            self.quarantine_restore_btn,
            "Restore file to original location"
        )

        # Create treeview for quarantined files
        builder = TreeviewBuilder(self.get_colors())
        tree_wrapper = builder.create(
            parent=self.frame,
            columns=[
                ('date', 'Quarantined', 140, 100, None),
                ('filename', 'Filename', 200, 100, None),
                ('size', 'Size', 80, 60, None),
                ('original_path', 'Original Path', 400, 200, None),
            ],
            style='Alerts.Treeview',
            sort_callback=self._on_sort_column,
            events={
                '<Button-3>': self._on_show_context_menu,
            }
        )

        self.quarantine_tree = tree_wrapper.treeview
        tree_wrapper.frame.pack(fill=tk.BOTH, expand=True)

    def refresh(self) -> None:
        """Refresh quarantined files list"""
        try:
            quarantine_dir = "/var/lib/clamav/quarantine"
            metadata_file = os.path.join(quarantine_dir, ".metadata.json")

            if not os.path.exists(quarantine_dir):
                return

            # Load metadata if exists
            metadata = {}
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                except Exception:
                    pass

            # Scan quarantine directory for files
            files = []
            try:
                for f in os.listdir(quarantine_dir):
                    if f.startswith('.'):
                        continue
                    fpath = os.path.join(quarantine_dir, f)
                    if os.path.isfile(fpath):
                        stat = os.stat(fpath)
                        original_path = metadata.get(f, {}).get('original_path', 'Unknown')
                        files.append({
                            'filename': f,
                            'mtime': stat.st_mtime,
                            'size': stat.st_size,
                            'original_path': original_path,
                            'full_path': fpath
                        })
            except PermissionError:
                return

            # Add formatted date and size strings
            for file_info in files:
                file_info['date'] = datetime.fromtimestamp(
                    file_info['mtime']
                ).strftime('%Y-%m-%d %H:%M')

                size_bytes = file_info['size']
                if size_bytes > 1024:
                    file_info['size_str'] = f"{size_bytes / 1024:.1f}KB"
                else:
                    file_info['size_str'] = f"{size_bytes}B"

            # Sort by selected column
            self._sort_files(files)

            # Build list of new values tuples for comparison
            new_values = [
                (f['date'], f['filename'], f['size_str'], f['original_path'])
                for f in files
            ]

            # Get current treeview values
            current_items = self.quarantine_tree.get_children()
            current_values = [
                self.quarantine_tree.item(item, 'values')
                for item in current_items
            ]

            # Compare - only update if data changed (silent refresh)
            if new_values == current_values:
                return

            # Data changed - save scroll position and selection
            scroll_pos = self.quarantine_tree.yview()
            selected = self.quarantine_tree.selection()
            selected_values = None
            if selected:
                try:
                    selected_values = self.quarantine_tree.item(selected[0], 'values')
                except Exception:
                    pass

            # Clear existing items
            for item in current_items:
                self.quarantine_tree.delete(item)

            # Insert new data
            self.quarantine_data = {}
            for file_info in files:
                item_id = self.quarantine_tree.insert('', tk.END, values=(
                    file_info['date'],
                    file_info['filename'],
                    file_info['size_str'],
                    file_info['original_path']
                ))
                self.quarantine_data[item_id] = file_info

            # Restore scroll position
            self.quarantine_tree.yview_moveto(scroll_pos[0])

            # Restore selection if the same item still exists
            if selected_values:
                for item in self.quarantine_tree.get_children():
                    if self.quarantine_tree.item(item, 'values') == selected_values:
                        self.quarantine_tree.selection_set(item)
                        break

        except Exception as e:
            print(f"Error refreshing quarantine: {e}")

    def _sort_files(self, files: list) -> None:
        """Sort files list in-place by current sort column"""
        sort_col = self.quarantine_sort_column

        if sort_col == 'date':
            files.sort(key=lambda x: x['mtime'], reverse=self.quarantine_sort_reverse)
        elif sort_col == 'size':
            files.sort(key=lambda x: x['size'], reverse=self.quarantine_sort_reverse)
        else:
            files.sort(
                key=lambda x: x.get(sort_col, ''),
                reverse=self.quarantine_sort_reverse
            )

    def _on_sort_column(self, column: str) -> None:
        """Handle column sort request"""
        if self.quarantine_sort_column == column:
            # Toggle reverse if same column
            self.quarantine_sort_reverse = not self.quarantine_sort_reverse
        else:
            # New column - default to reverse (descending)
            self.quarantine_sort_column = column
            self.quarantine_sort_reverse = True

        self.refresh()

    def _on_clean_all(self) -> None:
        """Delete all quarantined files"""
        if not messagebox.askyesno("Confirm", "Permanently delete ALL quarantined files?"):
            return

        # Use list-based subprocess (no shell injection risk)
        result = subprocess.run(
            ["pkexec", "/usr/local/bin/av-cleanup"],
            capture_output=True,
            text=True,
            timeout=60
        )

        messagebox.showinfo("Cleanup", result.stdout or "Quarantine cleaned")
        self.refresh()

    def _on_delete_selected(self) -> None:
        """Delete selected file from quarantine"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Delete", "No file selected")
            return

        item = selection[0]
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        if not messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete '{file_info['filename']}'?\n\nThis cannot be undone."
        ):
            return

        try:
            # Validate file path before deletion
            file_path = file_info['full_path']
            valid, err = validate_file_path(
                file_path,
                must_exist=True,
                allowed_dirs=["/var/lib/clamav/quarantine", "/var/quarantine"]
            )
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            result = subprocess.run(
                ["pkexec", "rm", "-f", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                messagebox.showinfo("Deleted", f"File deleted: {file_info['filename']}")
                self.refresh()
            else:
                messagebox.showerror("Error", f"Failed to delete: {result.stderr}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_restore_selected(self) -> None:
        """Restore selected file from quarantine"""
        selection = self.quarantine_tree.selection()
        if not selection:
            messagebox.showinfo("Restore", "No file selected")
            return

        item = selection[0]
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        original_path = file_info.get('original_path', 'Unknown')

        if original_path == 'Unknown':
            # Ask for destination
            dest_path = filedialog.asksaveasfilename(
                title="Choose restore location",
                initialfile=file_info['filename'],
                initialdir=os.path.expanduser("~")
            )
            if not dest_path:
                return
        else:
            if not messagebox.askyesno(
                "Confirm Restore",
                f"Restore '{file_info['filename']}' to:\n{original_path}\n\n"
                "WARNING: This file was quarantined as a potential threat!"
            ):
                return
            dest_path = original_path

        try:
            # Validate source file path before restore
            source_path = file_info['full_path']
            valid, err = validate_file_path(
                source_path,
                must_exist=True,
                allowed_dirs=["/var/lib/clamav/quarantine", "/var/quarantine"]
            )
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            # Validate destination path
            valid, err = validate_file_path(dest_path, must_exist=False)
            if not valid:
                messagebox.showerror("Validation Error", err)
                return

            result = subprocess.run(
                ["pkexec", "mv", source_path, dest_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                messagebox.showinfo("Restored", f"File restored to: {dest_path}")
                self.refresh()
            else:
                messagebox.showerror("Error", f"Failed to restore: {result.stderr}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_show_context_menu(self, event) -> None:
        """Show context menu for quarantine item"""
        item = self.quarantine_tree.identify_row(event.y)
        if not item:
            return

        self.quarantine_tree.selection_set(item)
        file_info = self.quarantine_data.get(item)
        if not file_info:
            return

        colors = self.get_colors()
        menu = tk.Menu(
            self.app.root,
            tearoff=0,
            bg=colors['bg_alt'],
            fg=colors['fg']
        )

        menu.add_command(
            label="Restore File",
            command=self._on_restore_selected
        )
        menu.add_command(
            label="Delete Permanently",
            command=self._on_delete_selected
        )
        menu.add_separator()

        # Truncate long paths in menu
        orig_path = file_info['original_path']
        display_path = orig_path[:50] if len(orig_path) > 50 else orig_path
        menu.add_command(
            label=f"Copy Path: {display_path}",
            command=lambda: self._copy_to_clipboard(file_info['original_path'])
        )

        menu.post(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to system clipboard"""
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.app.root.update()

    def _create_tooltip(self, widget, text: str) -> None:
        """
        Create tooltip for a widget.

        This is extracted from main_window.py until tooltips are
        moved to a shared utility module.
        """
        def show_tooltip(event):
            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")

            colors = self.get_colors()
            label = tk.Label(
                tooltip,
                text=text,
                background=colors['bg_alt'],
                foreground=colors['fg'],
                relief='solid',
                borderwidth=1,
                font=('Hack Nerd Font', 9),
                padx=5,
                pady=2
            )
            label.pack()

            widget.tooltip = tooltip

            def hide_tooltip(e):
                if hasattr(widget, 'tooltip'):
                    widget.tooltip.destroy()
                    del widget.tooltip

            widget.bind('<Leave>', hide_tooltip)
            tooltip.bind('<Leave>', hide_tooltip)

        widget.bind('<Enter>', show_tooltip)
