"""
Alerts Tab - Extracted from main_window.py
Displays and manages security alerts with filtering and threat intelligence
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import json
import csv
import re
import gzip
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

from ids_suite.ui.tabs.base_tab import BaseTab
from ids_suite.ui.components.treeview_builder import create_standard_alerts_tree
from ids_suite.core.utils import is_private_ip


class AlertsTab(BaseTab):
    """
    Security Alerts management tab.

    Features:
    - View alerts from Suricata/Snort
    - Filter by severity, engine, date range
    - Sort by any column
    - Hide/filter signatures, IPs, categories
    - Threat intelligence integration (VirusTotal, OTX, AbuseIPDB)
    - Export to CSV/JSON
    - Historical log viewing
    - Alert grouping by signature
    """

    def __init__(self, parent, app):
        """
        Initialize alerts tab.

        Args:
            parent: Parent widget (notebook)
            app: SecurityControlPanel instance
        """
        # Initialize state before calling super().__init__
        self.alerts_sort_column = 'timestamp'
        self.alerts_sort_reverse = True
        self.alerts_data: List[Dict[str, Any]] = []

        # Historical mode state
        self.historical_mode = False
        self.historical_alerts: List[Dict[str, Any]] = []
        self.selected_time_range = 'live'

        # UI element storage
        self.alerts_tree = None
        self.time_range_status = None
        self.date_filter_frame = None
        self.filter_count_label = None
        self.filter_btn = None

        # Variables for filters
        self.severity_var = tk.StringVar(value="all")
        self.date_from_var = tk.StringVar(value="")
        self.date_to_var = tk.StringVar(value="")
        self.engine_filter = tk.StringVar(value="All")

        # Filter listboxes for manager dialog
        self._filter_listboxes = {}

        super().__init__(parent, app)

    def _create_widgets(self) -> None:
        """Create alerts tab UI components"""
        # Time range presets frame
        time_frame = ttk.Frame(self.frame)
        time_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(
            time_frame,
            text="󰅐 Time Range:",
            font=('Hack Nerd Font', 10, 'bold')
        ).pack(side=tk.LEFT, padx=(0, 10))

        # Preset buttons
        factory = self.get_widget_factory()

        factory.create_button(
            time_frame, text="Live", width=6,
            command=lambda: self._set_time_range('live')
        ).pack(side=tk.LEFT, padx=2)

        factory.create_button(
            time_frame, text="24h", width=6,
            command=lambda: self._set_time_range('24h')
        ).pack(side=tk.LEFT, padx=2)

        factory.create_button(
            time_frame, text="7 days", width=6,
            command=lambda: self._set_time_range('7d')
        ).pack(side=tk.LEFT, padx=2)

        factory.create_button(
            time_frame, text="30 days", width=7,
            command=lambda: self._set_time_range('30d')
        ).pack(side=tk.LEFT, padx=2)

        factory.create_button(
            time_frame, text="Custom", width=7,
            command=self._show_custom_date_dialog
        ).pack(side=tk.LEFT, padx=2)

        # Status label showing current time range
        data_retention = getattr(self.app, 'data_retention_minutes', 120)
        self.time_range_status = ttk.Label(
            time_frame,
            text=f"󰋚 Live (last {data_retention} min)",
            foreground=self.get_colors()['green']
        )
        self.time_range_status.pack(side=tk.LEFT, padx=(15, 0))

        # Filter frame
        filter_frame = ttk.Frame(self.frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))

        # Engine filter (Suricata/Snort/Both)
        factory.create_label(filter_frame, text="Engine:").pack(side=tk.LEFT, padx=(0, 5))
        engine_values = ["All"]
        if self.app.suricata_engine.is_installed():
            engine_values.append("Suricata")
        if self.app.snort_engine.is_installed():
            engine_values.append("Snort")
        engine_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.engine_filter,
            values=engine_values,
            width=10,
            state='readonly'
        )
        engine_combo.pack(side=tk.LEFT, padx=(0, 15))
        engine_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh())

        factory.create_label(filter_frame, text="Severity:").pack(side=tk.LEFT, padx=(0, 5))
        severity_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.severity_var,
            values=["all", "1 - High", "2 - Medium", "3 - Low"],
            width=15
        )
        severity_combo.pack(side=tk.LEFT, padx=(0, 15))
        severity_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh())

        # Date range filter (hidden by default, shown in custom mode)
        self.date_filter_frame = ttk.Frame(filter_frame)
        factory.create_label(self.date_filter_frame, text="From:").pack(side=tk.LEFT, padx=(10, 5))
        date_from_entry = factory.create_entry(
            self.date_filter_frame,
            textvariable=self.date_from_var,
            width=12
        )
        date_from_entry.pack(side=tk.LEFT)
        self._create_tooltip(date_from_entry, "YYYY-MM-DD format")

        factory.create_label(self.date_filter_frame, text="To:").pack(side=tk.LEFT, padx=(10, 5))
        date_to_entry = factory.create_entry(
            self.date_filter_frame,
            textvariable=self.date_to_var,
            width=12
        )
        date_to_entry.pack(side=tk.LEFT)
        self._create_tooltip(date_to_entry, "YYYY-MM-DD format")

        # Bind date entry fields to refresh on change
        date_from_entry.bind('<Return>', lambda e: self._refresh_historical_alerts())
        date_from_entry.bind('<FocusOut>', lambda e: self._refresh_historical_alerts())
        date_to_entry.bind('<Return>', lambda e: self._refresh_historical_alerts())
        date_to_entry.bind('<FocusOut>', lambda e: self._refresh_historical_alerts())

        # Export button
        export_btn = factory.create_button(filter_frame, text="󰈔 Export", command=self._export_alerts)
        export_btn.pack(side=tk.RIGHT, padx=5)
        self._create_tooltip(export_btn, "Export alerts to CSV")

        # Manage filters button
        self.filter_btn = factory.create_button(
            filter_frame,
            text="󰈲 Filters",
            command=self._show_filter_manager
        )
        self.filter_btn.pack(side=tk.RIGHT, padx=5)
        self._create_tooltip(self.filter_btn, "Manage hidden signatures/IPs")

        # Filter count indicator
        colors = self.get_colors()
        self.filter_count_label = ttk.Label(
            filter_frame,
            text="",
            foreground=colors['orange']
        )
        self.filter_count_label.pack(side=tk.RIGHT, padx=5)

        factory.create_button(
            filter_frame,
            text="󰑐 Refresh",
            command=self.refresh
        ).pack(side=tk.RIGHT)

        # Alerts Treeview
        tree_frame = ttk.Frame(self.frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Create alerts tree using the builder
        tree_wrapper = create_standard_alerts_tree(
            parent=tree_frame,
            colors=colors,
            sort_callback=self._sort_alerts,
            on_double_click=self._show_alert_details,
            on_right_click=self._show_alert_context_menu
        )

        self.alerts_tree = tree_wrapper.treeview

        # Pack the tree frame
        tree_wrapper.frame.pack(fill=tk.BOTH, expand=True)

    def _format_alert_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display - compact for recent, full for older."""
        if not timestamp or len(timestamp) < 19:
            return timestamp or ''

        today = datetime.now().strftime('%Y-%m-%d')
        alert_date = timestamp[:10]

        if alert_date == today:
            return timestamp[11:19]  # HH:MM:SS
        else:
            return f"{timestamp[5:10]} {timestamp[11:16]}"  # MM-DD HH:MM

    def refresh(self) -> None:
        """Refresh alerts display"""
        # If in historical mode, use historical refresh instead
        if self.historical_mode:
            return self._refresh_historical_alerts()

        # Update the shared buffer first
        self.app._update_eve_buffer()

        severity_filter = self.severity_var.get()
        date_from = self.date_from_var.get().strip()
        date_to = self.date_to_var.get().strip()
        engine_filter = self.engine_filter.get().lower()

        # Build display data from buffer - filter for alert events only
        new_alerts_data = []
        for entry in self.app.eve_event_buffer:
            data = entry['data']
            timestamp = entry['timestamp']

            # Only process alert events
            if data.get('event_type') != 'alert':
                continue

            alert_data = data.get('alert', {})
            severity = alert_data.get('severity', 3)

            # Engine filter (Suricata is the source for EVE logs)
            if engine_filter != "all" and engine_filter != "suricata":
                continue

            # Severity filter
            if severity_filter != "all":
                filter_sev = int(severity_filter[0])
                if severity != filter_sev:
                    continue

            # Date range filter
            if date_from and timestamp[:10] < date_from:
                continue
            if date_to and timestamp[:10] > date_to:
                continue

            src_ip = data.get('src_ip', 'N/A')
            dst_ip = data.get('dest_ip', 'N/A')
            src_port = data.get('src_port', '')
            dst_port = data.get('dest_port', '')
            alert_entry = {
                'timestamp': timestamp,
                'severity': severity,
                'engine': 'Suricata',
                'signature': alert_data.get('signature', 'Unknown'),
                'category': alert_data.get('category', 'Unknown'),
                'source': f"{src_ip}:{src_port}" if src_port else src_ip,
                'destination': f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                'raw_data': data
            }
            new_alerts_data.append(alert_entry)

        # Sort alerts
        sort_col = self.alerts_sort_column
        if sort_col not in ['timestamp', 'signature', 'source', 'destination', 'category', 'intel']:
            sort_col = 'timestamp'
        new_alerts_data.sort(
            key=lambda x: x.get(sort_col, ''),
            reverse=self.alerts_sort_reverse
        )

        # Apply hidden filters
        new_alerts_data = self._apply_alert_filters(new_alerts_data)

        # Group similar alerts by signature (before limiting)
        new_alerts_data = self._group_alerts_by_signature(new_alerts_data)

        # Limit to last 200 grouped alerts
        new_alerts_data = new_alerts_data[-200:]

        # Apply threat intel status for all alerts (check both src and dst IPs)
        for alert in new_alerts_data:
            src_ip = alert['source'].split(':')[0] if ':' in alert['source'] else alert['source']
            dst_ip = alert['destination'].split(':')[0] if ':' in alert['destination'] else alert['destination']
            sev = alert['severity']

            # Get cached intel results for both IPs
            src_intel = self.app.ip_tracker.get_result(src_ip)
            dst_intel = self.app.ip_tracker.get_result(dst_ip)

            # Combine intel results - show worst case
            intel_status = self._combine_intel_status(src_intel, dst_intel)

            if intel_status:
                alert['intel'] = intel_status
            elif sev in (1, 2):
                # For severity 1-2 alerts, auto-lookup public IPs that haven't been checked
                lookup_needed = False
                if self.app.ip_tracker.should_lookup(src_ip) and not is_private_ip(src_ip):
                    self._auto_lookup_ip(src_ip)
                    lookup_needed = True
                if self.app.ip_tracker.should_lookup(dst_ip) and not is_private_ip(dst_ip):
                    self._auto_lookup_ip(dst_ip)
                    lookup_needed = True
                alert['intel'] = 'checking' if lookup_needed else '-'
            else:
                alert['intel'] = '-'

        # Build list of new values tuples for comparison (must match display format)
        new_values = []
        for alert in new_alerts_data:
            sev = alert['severity']
            cat = alert['category']
            new_values.append((
                self._format_alert_timestamp(alert['timestamp']),
                str(sev),
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ))

        # Get current treeview values
        current_items = self.alerts_tree.get_children()
        current_values = []
        for item in current_items:
            current_values.append(self.alerts_tree.item(item, 'values'))

        # Reverse current_values since we insert at position 0
        current_values = list(reversed(current_values))

        # Compare - only update if data changed
        if new_values == current_values:
            # No changes, skip visual update entirely
            self.alerts_data = new_alerts_data
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.alerts_tree.yview()
        selected = self.alerts_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.alerts_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate
        for item in current_items:
            self.alerts_tree.delete(item)

        self.alerts_data = new_alerts_data

        for alert in new_alerts_data:
            sev = alert['severity']
            tag = 'high' if sev == 1 else 'medium' if sev == 2 else 'low'
            cat = alert['category']

            self.alerts_tree.insert('', 0, values=(
                self._format_alert_timestamp(alert['timestamp']),
                sev,
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ), tags=(tag,))

        # Restore scroll position
        self.alerts_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.alerts_tree.get_children():
                if self.alerts_tree.item(item, 'values') == selected_values:
                    self.alerts_tree.selection_set(item)
                    break

    def _sort_alerts(self, column: str) -> None:
        """Sort alerts by column"""
        if self.alerts_sort_column == column:
            self.alerts_sort_reverse = not self.alerts_sort_reverse
        else:
            self.alerts_sort_column = column
            self.alerts_sort_reverse = True

        self.refresh()

    def _set_time_range(self, preset: str) -> None:
        """Set time range preset and load appropriate data"""
        self.selected_time_range = preset
        today = datetime.now()
        colors = self.get_colors()

        if preset == 'live':
            # Switch back to live mode
            self.historical_mode = False
            self.historical_alerts = []
            self.date_from_var.set("")
            self.date_to_var.set("")
            self.date_filter_frame.pack_forget()
            self.time_range_status.configure(
                text=f"󰋚 Live (last {self.app.data_retention_minutes} min)",
                foreground=colors['green']
            )
            self.refresh()
        elif preset == '24h':
            yesterday = (today - timedelta(days=1)).strftime('%Y-%m-%d')
            today_str = today.strftime('%Y-%m-%d')
            self._load_historical_logs(yesterday, today_str, "Last 24 hours")
        elif preset == '7d':
            week_ago = (today - timedelta(days=7)).strftime('%Y-%m-%d')
            today_str = today.strftime('%Y-%m-%d')
            self._load_historical_logs(week_ago, today_str, "Last 7 days")
        elif preset == '30d':
            month_ago = (today - timedelta(days=30)).strftime('%Y-%m-%d')
            today_str = today.strftime('%Y-%m-%d')
            self._load_historical_logs(month_ago, today_str, "Last 30 days")

    def _show_custom_date_dialog(self) -> None:
        """Show dialog for custom date range selection"""
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Custom Date Range")
        dialog.geometry("350x200")
        colors = self.get_colors()
        dialog.configure(bg=colors['bg'])
        dialog.transient(self.app.root)
        dialog.grab_set()

        ttk.Label(
            dialog,
            text="󰃭 Select Date Range",
            font=('Hack Nerd Font', 12, 'bold')
        ).pack(pady=10)

        # Date inputs
        input_frame = ttk.Frame(dialog)
        input_frame.pack(pady=10)

        today = datetime.now()
        week_ago = (today - timedelta(days=7)).strftime('%Y-%m-%d')
        today_str = today.strftime('%Y-%m-%d')

        ttk.Label(input_frame, text="From:").grid(row=0, column=0, padx=5, pady=5)
        from_var = tk.StringVar(value=week_ago)
        factory = self.get_widget_factory()
        from_entry = factory.create_entry(input_frame, textvariable=from_var, width=15)
        from_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(input_frame, text="To:").grid(row=1, column=0, padx=5, pady=5)
        to_var = tk.StringVar(value=today_str)
        to_entry = factory.create_entry(input_frame, textvariable=to_var, width=15)
        to_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(
            dialog,
            text="Format: YYYY-MM-DD",
            foreground=colors['gray']
        ).pack()

        def apply_range():
            date_from = from_var.get().strip()
            date_to = to_var.get().strip()

            # Validate dates
            try:
                datetime.strptime(date_from, '%Y-%m-%d')
                datetime.strptime(date_to, '%Y-%m-%d')
            except ValueError:
                messagebox.showerror("Invalid Date", "Please use YYYY-MM-DD format")
                return

            dialog.destroy()
            self.selected_time_range = 'custom'
            self._load_historical_logs(date_from, date_to, f"{date_from} to {date_to}")

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)
        factory.create_button(btn_frame, text="Load", command=apply_range).pack(side=tk.LEFT, padx=5)
        factory.create_button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _load_historical_logs(self, date_from: str, date_to: str, label: str) -> None:
        """Load historical logs from files within date range"""
        def do_load():
            self.app.show_progress(f"Loading logs for {label}...")

            try:
                log_dir = Path("/var/log/suricata")
                all_alerts = []

                # Find all relevant log files
                log_files = []

                # Current eve.json
                current_log = log_dir / "eve.json"
                if current_log.exists():
                    log_files.append(('current', current_log))

                # Rotated logs (eve.json-YYYYMMDD and eve.json-YYYYMMDD.gz)
                for f in log_dir.glob("eve.json-*"):
                    log_files.append(('rotated', f))

                # Sort by modification time (newest first)
                log_files.sort(key=lambda x: x[1].stat().st_mtime, reverse=True)

                parsed_count = 0
                for file_type, log_file in log_files:
                    try:
                        # Check if file might contain data in our range
                        file_date = None
                        if file_type == 'rotated':
                            # Extract date from filename like eve.json-20260104
                            name = log_file.name
                            if name.endswith('.gz'):
                                name = name[:-3]
                            date_part = name.split('-')[-1]
                            if len(date_part) == 8 and date_part.isdigit():
                                file_date = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
                                # Skip if file is outside our range
                                if file_date < date_from or file_date > date_to:
                                    continue

                        # Read the file
                        if str(log_file).endswith('.gz'):
                            with gzip.open(log_file, 'rt', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                        else:
                            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()

                        # Parse each line
                        for line in lines:
                            try:
                                data = json.loads(line.strip())
                                if data.get('event_type') != 'alert':
                                    continue

                                timestamp = data.get('timestamp', '')[:19]
                                event_date = timestamp[:10]

                                # Filter by date range
                                if event_date < date_from or event_date > date_to:
                                    continue

                                alert_data = data.get('alert', {})
                                severity = alert_data.get('severity', 3)
                                src_ip = data.get('src_ip', 'N/A')
                                dst_ip = data.get('dest_ip', 'N/A')
                                src_port = data.get('src_port', '')
                                dst_port = data.get('dest_port', '')

                                all_alerts.append({
                                    'timestamp': timestamp,
                                    'severity': severity,
                                    'engine': 'Suricata',
                                    'signature': alert_data.get('signature', 'Unknown'),
                                    'category': alert_data.get('category', 'Unknown'),
                                    'source': f"{src_ip}:{src_port}" if src_port else src_ip,
                                    'destination': f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                                    'raw_data': data
                                })
                                parsed_count += 1

                            except (json.JSONDecodeError, KeyError):
                                continue

                    except Exception as e:
                        print(f"Error reading {log_file}: {e}")
                        continue

                # Sort by timestamp (newest first)
                all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)

                def update_ui():
                    colors = self.get_colors()
                    self.app.hide_progress()
                    self.historical_mode = True
                    self.historical_alerts = all_alerts
                    self.date_from_var.set(date_from)
                    self.date_to_var.set(date_to)

                    self.time_range_status.configure(
                        text=f"󰋚 Historical: {label} ({len(all_alerts)} alerts)",
                        foreground=colors['cyan']
                    )

                    # Show the date filter frame for manual adjustment
                    self.date_filter_frame.pack(side=tk.LEFT, padx=(10, 0))

                    # Refresh display with historical data
                    self._refresh_historical_alerts()

                self.app.root.after(0, update_ui)

            except Exception as e:
                def show_error():
                    self.app.hide_progress()
                    messagebox.showerror("Error", f"Failed to load logs: {str(e)}")
                self.app.root.after(0, show_error)

        threading.Thread(target=do_load, daemon=True).start()

    def _refresh_historical_alerts(self) -> None:
        """Refresh alerts display with historical data (silent refresh)"""
        if not self.historical_mode:
            # Not in historical mode, nothing to do
            return

        severity_filter = self.severity_var.get()
        date_from = self.date_from_var.get().strip()
        date_to = self.date_to_var.get().strip()

        # Filter historical alerts
        filtered = []
        for alert in self.historical_alerts:
            # Severity filter
            if severity_filter != "all":
                filter_sev = int(severity_filter[0])
                if alert['severity'] != filter_sev:
                    continue

            # Additional date filtering
            timestamp = alert['timestamp']
            if date_from and timestamp[:10] < date_from:
                continue
            if date_to and timestamp[:10] > date_to:
                continue

            filtered.append(alert)

        # Sort
        sort_col = self.alerts_sort_column
        filtered.sort(key=lambda x: x.get(sort_col, ''), reverse=self.alerts_sort_reverse)

        # Apply hidden filters
        filtered = self._apply_alert_filters(filtered)

        # Group similar alerts by signature
        filtered = self._group_alerts_by_signature(filtered)

        # Limit display to 500 grouped alerts for performance
        filtered = filtered[:500]

        # Add intel status for historical alerts (check both src and dst IPs)
        for alert in filtered:
            src_ip = alert['source'].split(':')[0] if ':' in alert['source'] else alert['source']
            dst_ip = alert['destination'].split(':')[0] if ':' in alert['destination'] else alert['destination']

            # Get cached intel results for both IPs
            src_intel = self.app.ip_tracker.get_result(src_ip)
            dst_intel = self.app.ip_tracker.get_result(dst_ip)

            # Combine intel results - show worst case
            intel_status = self._combine_intel_status(src_intel, dst_intel)
            alert['intel'] = intel_status if intel_status else '-'

        # Build list of new values tuples for comparison (must match display format)
        new_values = []
        for alert in filtered:
            sev = alert['severity']
            cat = alert['category']
            new_values.append((
                self._format_alert_timestamp(alert['timestamp']),
                str(sev),
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ))

        # Get current treeview values
        current_items = self.alerts_tree.get_children()
        current_values = [self.alerts_tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.alerts_data = filtered
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.alerts_tree.yview()
        selected = self.alerts_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.alerts_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate
        for item in current_items:
            self.alerts_tree.delete(item)

        self.alerts_data = filtered

        for alert in filtered:
            sev = alert['severity']
            tag = 'high' if sev == 1 else ('medium' if sev == 2 else 'low')
            cat = alert['category']
            self.alerts_tree.insert('', tk.END, values=(
                self._format_alert_timestamp(alert['timestamp']),
                sev,
                alert['signature'],
                alert['source'],
                alert['destination'],
                cat[:8] if len(cat) > 8 else cat,
                alert['intel']
            ), tags=(tag,))

        # Restore scroll position
        self.alerts_tree.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.alerts_tree.get_children():
                if self.alerts_tree.item(item, 'values') == selected_values:
                    self.alerts_tree.selection_set(item)
                    break

    def _show_alert_details(self, event) -> None:
        """Show alert details in popup window"""
        selection = self.alerts_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.alerts_tree.item(item, 'values')
        # Columns: timestamp, sev, signature, source, destination, category, intel
        display_ts, sev, signature, source, destination = values[0], values[1], values[2], values[3], values[4]

        # Find the full alert data by matching signature and source
        alert_data = None
        alert_obj = None
        for alert in self.alerts_data:
            if alert['signature'] == signature and alert['source'] == source:
                if str(alert['severity']) == str(sev):
                    alert_data = alert.get('raw_data', {})
                    alert_obj = alert
                    break

        if not alert_data:
            return

        # Create popup window
        colors = self.get_colors()
        popup = tk.Toplevel(self.app.root)
        popup.title(f"Alert Details - {signature[:50]}")
        popup.geometry("700x500")
        popup.configure(bg=colors['bg'])

        # Header - get severity from alert_obj
        header_frame = ttk.Frame(popup)
        header_frame.pack(fill=tk.X, padx=10, pady=10)

        sev = str(alert_obj.get('severity', '3')) if alert_obj else '3'
        sev_color = colors['red'] if sev == '1' else colors['orange'] if sev == '2' else colors['yellow']
        engine = alert_obj.get('engine', 'Unknown') if alert_obj else 'Unknown'
        intel = values[5] if len(values) > 5 else '-'
        tk.Label(
            header_frame,
            text=f"Severity {sev} ({engine}) | Intel: {intel}",
            font=('Hack Nerd Font', 12, 'bold'),
            bg=colors['bg'],
            fg=sev_color
        ).pack(side=tk.LEFT)
        tk.Label(
            header_frame,
            text=timestamp,
            font=('Hack Nerd Font', 10),
            bg=colors['bg'],
            fg=colors['gray']
        ).pack(side=tk.RIGHT)

        # Signature
        ttk.Label(
            popup,
            text=signature,
            font=('Hack Nerd Font', 11, 'bold'),
            wraplength=680
        ).pack(anchor=tk.W, padx=10, pady=5)

        # Connection info
        conn_frame = ttk.Frame(popup)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(conn_frame, text=f"Source: {source}").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Label(conn_frame, text=f"Destination: {destination}").pack(side=tk.LEFT)

        # Full JSON data
        ttk.Label(
            popup,
            text="Raw Event Data:",
            font=('Hack Nerd Font', 10, 'bold')
        ).pack(anchor=tk.W, padx=10, pady=(10, 5))

        factory = self.get_widget_factory()
        json_text = factory.create_textbox(
            popup,
            height=20,
            bg=colors['bg_alt'],
            fg=colors['fg'],
            font=('Hack Nerd Font', 9)
        )
        json_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        json_text.insert(tk.END, json.dumps(alert_data, indent=2))
        json_text.configure(state='disabled')

    def _show_alert_context_menu(self, event) -> None:
        """Show context menu on right-click"""
        item = self.alerts_tree.identify_row(event.y)
        if not item:
            return

        self.alerts_tree.selection_set(item)
        values = self.alerts_tree.item(item, 'values')
        # Columns: timestamp, sev, signature, source, destination, category, intel
        signature = values[2]
        # Strip x{count} suffix from grouped signatures
        signature = re.sub(r'\s+x\d+$', '', signature)
        src_ip = values[3].split(':')[0] if ':' in str(values[3]) else str(values[3])
        dest_ip = values[4].split(':')[0] if ':' in str(values[4]) else str(values[4])

        colors = self.get_colors()
        menu = tk.Menu(self.app.root, tearoff=0, bg=colors['bg_alt'], fg=colors['fg'])
        menu.add_command(label="View Details", command=lambda: self._show_alert_details(None))
        menu.add_command(
            label="Copy Row",
            command=lambda: self._copy_to_clipboard('\t'.join(str(v) for v in values))
        )
        menu.add_separator()
        menu.add_command(
            label=f"Search Source: {src_ip}",
            command=lambda: self.app.search_var.set(src_ip)
        )
        menu.add_command(
            label=f"Search Dest: {dest_ip}",
            command=lambda: self.app.search_var.set(dest_ip)
        )
        menu.add_command(
            label=f"Search Signature",
            command=lambda: self.app.search_var.set(signature)
        )
        menu.add_separator()

        # Threat Intelligence submenu
        ti_menu = tk.Menu(menu, tearoff=0, bg=colors['bg_alt'], fg=colors['fg'])
        ti_menu.add_command(
            label=f"VirusTotal: {src_ip}",
            command=lambda: self._lookup_virustotal(src_ip)
        )
        ti_menu.add_command(
            label=f"VirusTotal: {dest_ip}",
            command=lambda: self._lookup_virustotal(dest_ip)
        )
        ti_menu.add_separator()
        ti_menu.add_command(
            label=f"OTX: {src_ip}",
            command=lambda: self._lookup_otx(src_ip)
        )
        ti_menu.add_command(
            label=f"OTX: {dest_ip}",
            command=lambda: self._lookup_otx(dest_ip)
        )
        menu.add_cascade(label="󰊕 Threat Intel", menu=ti_menu)

        menu.add_separator()

        # Hide/Filter submenu
        category = values[4] if len(values) > 4 else ''
        hide_menu = tk.Menu(menu, tearoff=0, bg=colors['bg_alt'], fg=colors['fg'])
        hide_menu.add_command(
            label=f"Hide Signature: {signature[:40]}...",
            command=lambda s=signature: self._hide_signature(s)
        )
        hide_menu.add_command(
            label=f"Hide Source IP: {src_ip}",
            command=lambda ip=src_ip: self._hide_src_ip(ip)
        )
        hide_menu.add_command(
            label=f"Hide Dest IP: {dest_ip}",
            command=lambda ip=dest_ip: self._hide_dest_ip(ip)
        )
        if category:
            hide_menu.add_command(
                label=f"Hide Category: {category}",
                command=lambda c=category: self._hide_category(c)
            )
        hide_menu.add_separator()
        hide_menu.add_command(label="Manage Filters...", command=self._show_filter_manager)
        menu.add_cascade(label="󰈲 Hide/Filter", menu=hide_menu)

        menu.post(event.x_root, event.y_root)

    def _lookup_virustotal(self, ip: str) -> None:
        """Lookup IP on VirusTotal and show results"""
        def do_lookup():
            result = self.app.vt_client.lookup_ip(ip)
            def show():
                self.app._add_to_lookup_history(ip, 'VirusTotal', result)
                self._show_threat_intel_result("VirusTotal", ip, result)
            self.app.root.after(0, show)

        self.app.show_progress("Looking up on VirusTotal...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _lookup_otx(self, ip: str) -> None:
        """Lookup IP on AlienVault OTX and show results"""
        def do_lookup():
            result = self.app.otx_client.lookup_ip(ip)
            def show():
                self.app._add_to_lookup_history(ip, 'OTX', result)
                self._show_threat_intel_result("OTX", ip, result)
            self.app.root.after(0, show)

        self.app.show_progress("Looking up on OTX...")
        threading.Thread(target=do_lookup, daemon=True).start()

    def _auto_lookup_ip(self, ip: str) -> None:
        """Automatically lookup IP via AbuseIPDB and record result (for severity 1 alerts)"""
        def do_lookup():
            try:
                # Use AbuseIPDB for auto-lookup (best for IP reputation)
                result = self.app.abuseipdb_client.lookup_ip(ip)

                # Determine danger status based on abuse score
                if 'error' in result:
                    status = 'error'
                    details = {'error': result.get('error', 'Unknown error')}
                else:
                    # AbuseIPDB client returns snake_case field names
                    abuse_score = result.get('abuse_score', 0)
                    total_reports = result.get('total_reports', 0)

                    if abuse_score >= 50 or total_reports >= 10:
                        status = 'DANGER'
                    elif abuse_score >= 25 or total_reports >= 3:
                        status = 'suspect'
                    else:
                        status = 'safe'

                    # Store details for Intel tab display
                    details = {
                        'abuseConfidenceScore': abuse_score,
                        'totalReports': total_reports,
                        'countryCode': result.get('country', ''),
                        'isp': result.get('isp', ''),
                        'domain': result.get('domain', ''),
                        'usageType': result.get('usage_type', '')
                    }

                # Record result in tracker with source and details
                self.app.ip_tracker.record_lookup(ip, status, source='AbuseIPDB', details=details)

                # Schedule UI refresh on main thread - also refresh Intel tab
                def update_ui():
                    self.refresh()
                    if hasattr(self.app, '_refresh_intel_from_tracker'):
                        self.app._refresh_intel_from_tracker()

                self.app.root.after(100, update_ui)

            except Exception as e:
                print(f"Auto-lookup error for {ip}: {e}")
                self.app.ip_tracker.record_lookup(ip, 'error', source='AbuseIPDB',
                                                   details={'error': str(e)})

        threading.Thread(target=do_lookup, daemon=True).start()

    def _show_threat_intel_result(self, source: str, indicator: str, result: dict) -> None:
        """Display threat intelligence lookup result in a dialog"""
        self.app.hide_progress()

        colors = self.get_colors()
        dialog = tk.Toplevel(self.app.root)
        dialog.title(f"{source} Lookup: {indicator}")
        dialog.geometry("500x400")
        dialog.configure(bg=colors['bg'])

        # Header
        header = ttk.Label(
            dialog,
            text=f"󰊕 {source} Results",
            font=('Hack Nerd Font', 14, 'bold')
        )
        header.pack(pady=10)

        # Result display - use ScrolledText for tag_configure support
        text = scrolledtext.ScrolledText(
            dialog,
            height=15,
            bg=colors['bg_alt'],
            fg=colors['fg'],
            font=('Hack Nerd Font', 10)
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        if 'error' in result:
            text.insert(tk.END, f"Error: {result['error']}\n\n")
            text.insert(tk.END, "Tips:\n")
            text.insert(tk.END, "- Check if API key is configured in Settings > Threat Intel\n")
            text.insert(tk.END, "- Check your internet connection\n")
            text.insert(tk.END, "- Public API has rate limits (4 req/min for VirusTotal)\n")
        else:
            text.insert(tk.END, f"Indicator: {result.get('indicator', indicator)}\n")
            text.insert(tk.END, f"Type: {result.get('type', 'Unknown')}\n\n")

            if source == "VirusTotal":
                malicious = result.get('malicious', 0)
                suspicious = result.get('suspicious', 0)
                harmless = result.get('harmless', 0)

                # Configure tags
                text.tag_configure('danger', foreground=colors['red'])
                text.tag_configure('warning', foreground=colors['orange'])
                text.tag_configure('safe', foreground=colors['green'])

                # Threat score
                if malicious > 0:
                    text.insert(tk.END, f"⚠ MALICIOUS: {malicious} detections\n", 'danger')
                elif suspicious > 0:
                    text.insert(tk.END, f"⚡ SUSPICIOUS: {suspicious} flags\n", 'warning')
                else:
                    text.insert(tk.END, f"✓ CLEAN: No detections\n", 'safe')

                text.insert(tk.END, f"\nReputation Score: {result.get('reputation', 0)}\n")
                text.insert(tk.END, f"Country: {result.get('country', 'Unknown')}\n")
                text.insert(tk.END, f"AS Owner: {result.get('as_owner', 'Unknown')}\n")
                text.insert(tk.END, f"\nStats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless\n")

            elif source == "OTX":
                pulse_count = result.get('pulse_count', 0)

                # Configure tags
                text.tag_configure('danger', foreground=colors['red'])
                text.tag_configure('safe', foreground=colors['green'])

                if pulse_count > 0:
                    text.insert(tk.END, f"⚠ Found in {pulse_count} threat pulse(s)\n\n", 'danger')
                    text.insert(tk.END, "Related Pulses:\n")
                    for pulse in result.get('pulses', []):
                        text.insert(tk.END, f"  • {pulse}\n")
                else:
                    text.insert(tk.END, "✓ Not found in any threat pulses\n", 'safe')

                text.insert(tk.END, f"\nCountry: {result.get('country', 'Unknown')}\n")

        text.configure(state='disabled')

    # ==================== Alert Filtering Methods ====================

    def _hide_signature(self, signature: str) -> None:
        """Add signature to hidden filter (persisted)"""
        self.app.hidden_signatures.add(signature)
        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _hide_src_ip(self, ip: str) -> None:
        """Add source IP to hidden filter (persisted)"""
        self.app.hidden_src_ips.add(ip)
        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _hide_dest_ip(self, ip: str) -> None:
        """Add destination IP to hidden filter (persisted)"""
        self.app.hidden_dest_ips.add(ip)
        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _hide_category(self, category: str) -> None:
        """Add category to hidden filter (persisted)"""
        self.app.hidden_categories.add(category)
        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _update_filter_count(self) -> None:
        """Update filter count indicator"""
        total = (len(self.app.hidden_signatures) + len(self.app.hidden_src_ips) +
                 len(self.app.hidden_dest_ips) + len(self.app.hidden_categories))
        if total > 0:
            self.filter_count_label.configure(text=f"({total} filters)")
        else:
            self.filter_count_label.configure(text="")

    def _show_filter_manager(self) -> None:
        """Show dialog to manage hidden filters"""
        colors = self.get_colors()
        dialog = tk.Toplevel(self.app.root)
        dialog.title("Manage Alert Filters")
        dialog.geometry("600x500")
        dialog.configure(bg=colors['bg'])
        dialog.transient(self.app.root)

        # Header
        ttk.Label(
            dialog,
            text="󰈲 Alert Filters",
            font=('Hack Nerd Font', 14, 'bold')
        ).pack(pady=10)
        ttk.Label(
            dialog,
            text="Items in these lists will be hidden from alerts view",
            foreground=colors['gray']
        ).pack()

        # Notebook for filter categories
        filter_nb = ttk.Notebook(dialog)
        filter_nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create listboxes for each filter type
        self._filter_listboxes = {}

        filter_types = [
            ('signatures', 'Hidden Signatures', self.app.hidden_signatures),
            ('src_ips', 'Hidden Source IPs', self.app.hidden_src_ips),
            ('dest_ips', 'Hidden Dest IPs', self.app.hidden_dest_ips),
            ('categories', 'Hidden Categories', self.app.hidden_categories)
        ]

        factory = self.get_widget_factory()

        for key, title, filter_set in filter_types:
            frame = ttk.Frame(filter_nb)
            filter_nb.add(frame, text=title)

            # Listbox with scrollbar
            list_frame = ttk.Frame(frame)
            list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            scrollbar = ttk.Scrollbar(list_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            listbox = tk.Listbox(
                list_frame,
                bg=colors['bg_alt'],
                fg=colors['fg'],
                font=('Hack Nerd Font', 10),
                selectmode=tk.EXTENDED,
                yscrollcommand=scrollbar.set
            )
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)

            for item in sorted(filter_set):
                listbox.insert(tk.END, item)

            self._filter_listboxes[key] = (listbox, filter_set)

            # Remove button
            btn_frame = ttk.Frame(frame)
            btn_frame.pack(fill=tk.X, padx=5, pady=5)
            factory.create_button(
                btn_frame,
                text="Remove Selected",
                command=lambda k=key: self._remove_selected_filter(k)
            ).pack(side=tk.LEFT, padx=5)
            factory.create_button(
                btn_frame,
                text="Clear All",
                command=lambda k=key: self._clear_filter(k)
            ).pack(side=tk.LEFT, padx=5)

        # Bottom buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        factory.create_button(
            btn_frame,
            text="Clear All Filters",
            command=lambda: self._clear_all_filters(dialog)
        ).pack(side=tk.LEFT, padx=5)
        factory.create_button(
            btn_frame,
            text="Close",
            command=dialog.destroy
        ).pack(side=tk.RIGHT, padx=5)

    def _remove_selected_filter(self, filter_key: str) -> None:
        """Remove selected items from filter"""
        if filter_key not in self._filter_listboxes:
            return

        listbox, filter_set = self._filter_listboxes[filter_key]
        selected = listbox.curselection()

        # Get items to remove (in reverse order to maintain indices)
        items_to_remove = [listbox.get(i) for i in selected]

        for item in items_to_remove:
            filter_set.discard(item)

        # Refresh listbox
        listbox.delete(0, tk.END)
        for item in sorted(filter_set):
            listbox.insert(tk.END, item)

        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _clear_filter(self, filter_key: str) -> None:
        """Clear all items from a specific filter"""
        if filter_key not in self._filter_listboxes:
            return

        listbox, filter_set = self._filter_listboxes[filter_key]
        filter_set.clear()
        listbox.delete(0, tk.END)

        self._update_filter_count()
        self.app.save_filters()
        self.refresh()

    def _clear_all_filters(self, dialog) -> None:
        """Clear all filters"""
        self.app.hidden_signatures.clear()
        self.app.hidden_src_ips.clear()
        self.app.hidden_dest_ips.clear()
        self.app.hidden_categories.clear()
        self._update_filter_count()
        self.app.save_filters()
        self.refresh()
        dialog.destroy()

    def _combine_intel_status(self, src_intel: Optional[str], dst_intel: Optional[str]) -> Optional[str]:
        """
        Combine intel status from source and destination IPs.

        Returns the most severe status, prioritizing:
        DANGER > suspect > error > checking > safe > None

        Args:
            src_intel: Intel status for source IP (or None)
            dst_intel: Intel status for destination IP (or None)

        Returns:
            Combined status string or None if no intel available
        """
        # Priority order (highest to lowest severity)
        priority = {'DANGER': 5, 'suspect': 4, 'error': 3, 'checking': 2, 'safe': 1}

        src_priority = priority.get(src_intel, 0) if src_intel else 0
        dst_priority = priority.get(dst_intel, 0) if dst_intel else 0

        if src_priority == 0 and dst_priority == 0:
            return None

        # Return the most severe status
        if src_priority >= dst_priority:
            return src_intel
        return dst_intel

    def _apply_alert_filters(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply hidden filters to alert list"""
        if not (self.app.hidden_signatures or self.app.hidden_src_ips or
                self.app.hidden_dest_ips or self.app.hidden_categories):
            return alerts

        filtered = []
        for alert in alerts:
            signature = alert.get('signature', '')
            src = alert.get('source', '').split(':')[0]
            dest = alert.get('destination', '').split(':')[0]
            category = alert.get('category', '')

            # Skip if any filter matches
            if signature in self.app.hidden_signatures:
                continue
            if src in self.app.hidden_src_ips:
                continue
            if dest in self.app.hidden_dest_ips:
                continue
            if category in self.app.hidden_categories:
                continue

            filtered.append(alert)

        return filtered

    def _group_alerts_by_signature(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Group similar alerts by signature, appending x{count} for duplicates.

        Groups alerts with the same signature, keeping the most recent occurrence
        and appending a count indicator (e.g., "ET INFO EXTERNAL IP Lookup x10").
        """
        if not alerts:
            return alerts

        # Group by signature
        signature_groups = {}
        for alert in alerts:
            sig = alert.get('signature', 'Unknown')
            if sig not in signature_groups:
                signature_groups[sig] = []
            signature_groups[sig].append(alert)

        # Build grouped result - use most recent alert from each group
        grouped_alerts = []
        for sig, group in signature_groups.items():
            # Sort group by timestamp descending to get most recent
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()  # Copy to avoid modifying original

            count = len(group)
            if count > 1:
                # Append count to signature
                most_recent['signature'] = f"{sig} x{count}"
                most_recent['_group_count'] = count  # Store for potential use

            grouped_alerts.append(most_recent)

        # Sort grouped alerts by timestamp (most recent first for display)
        grouped_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return grouped_alerts

    def _export_alerts(self) -> None:
        """Export alerts to CSV file"""
        if not self.alerts_data:
            messagebox.showinfo("Export", "No alerts to export")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        if not filepath:
            return

        try:
            if filepath.endswith('.json'):
                with open(filepath, 'w') as f:
                    # Export raw data without the raw_data field to avoid duplication
                    export_data = [{k: v for k, v in a.items() if k != 'raw_data'} for a in self.alerts_data]
                    json.dump(export_data, f, indent=2)
            else:
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Severity', 'Signature', 'Source', 'Destination', 'Category'])
                    for alert in self.alerts_data:
                        writer.writerow([
                            alert['timestamp'], alert['severity'], alert['signature'],
                            alert['source'], alert['destination'], alert['category']
                        ])

            messagebox.showinfo("Export", f"Exported {len(self.alerts_data)} alerts to {filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _copy_to_clipboard(self, text: str) -> None:
        """Copy text to clipboard"""
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)

    def _create_tooltip(self, widget, text: str) -> None:
        """Create tooltip for widget"""
        if hasattr(self.app, 'create_tooltip'):
            self.app.create_tooltip(widget, text)
