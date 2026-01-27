"""
Traffic Tab - Network Traffic Analysis
Extracted from main_window.py SecurityControlPanel
"""

import tkinter as tk
from tkinter import ttk
import json
from datetime import datetime
from typing import Dict, List, TYPE_CHECKING

from ids_suite.ui.tabs.base_tab import BaseTab
from ids_suite.ui.components.treeview_builder import create_standard_traffic_tree

if TYPE_CHECKING:
    from ids_suite.ui.main_window import SecurityControlPanel


class TrafficTab(BaseTab):
    """
    Network Traffic Analysis Tab

    Displays network traffic events (HTTP, TLS, SSH, SMB, RDP) from Suricata EVE logs.
    Features:
    - Protocol filtering
    - Traffic grouping by destination
    - Detailed traffic inspection
    - VirusTotal integration
    - Alert correlation
    """

    def __init__(self, parent: tk.Widget, app: 'SecurityControlPanel'):
        """
        Initialize Traffic tab.

        Args:
            parent: Parent widget (notebook)
            app: Main application instance
        """
        # Initialize instance variables before calling super().__init__
        self.traffic_data: List[Dict] = []
        self.traffic_sort_column: str = 'timestamp'
        self.traffic_sort_reverse: bool = True

        # Initialize parent class (calls _create_widgets)
        super().__init__(parent, app)

    def _create_widgets(self) -> None:
        """Create Traffic tab UI"""
        # Header with controls
        header_frame, _ = self.create_header(
            self.frame,
            title="Network Traffic Analysis",
            icon="󰖟"
        )

        # Protocol filter
        self.app.widgets.create_label(header_frame, text="Protocol:").pack(
            side=tk.LEFT, padx=(20, 5)
        )
        self.traffic_proto_filter = tk.StringVar(value="all")
        proto_combo = ttk.Combobox(
            header_frame,
            textvariable=self.traffic_proto_filter,
            values=["all", "HTTP", "TLS", "SSH", "SMB", "RDP"],
            width=8,
            state='readonly'
        )
        proto_combo.pack(side=tk.LEFT, padx=(0, 10))
        proto_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh())

        # Ungroup toggle (grouped by destination is default)
        self.traffic_ungrouped = tk.BooleanVar(value=False)
        self.traffic_ungroup_btn = self.app.widgets.create_button(
            header_frame,
            text="󰘷 Ungroup",
            command=self._toggle_traffic_grouping
        )
        self.traffic_ungroup_btn.pack(side=tk.LEFT, padx=(10, 5))

        # Refresh button
        self.create_refresh_button(header_frame)

        # Stats summary
        self.traffic_stats_label = ttk.Label(
            header_frame,
            text="",
            foreground=self.get_colors()['cyan']
        )
        self.traffic_stats_label.pack(side=tk.RIGHT, padx=10)

        # Traffic Treeview using standard builder
        colors = self.get_colors()
        self.traffic_tree = create_standard_traffic_tree(
            parent=self.frame,
            colors=colors,
            sort_callback=self.sort_traffic
        )

        # Add event bindings for context menu and details
        self.traffic_tree.bind('<Button-3>', self._show_traffic_context_menu)
        self.traffic_tree.bind('<Double-1>', self._show_traffic_details)

        # Pack the treeview frame
        self.traffic_tree.frame.pack(fill=tk.BOTH, expand=True)

    def refresh(self) -> None:
        """Refresh traffic analysis from shared EVE buffer"""
        # Update the shared buffer first
        self.app._update_eve_buffer()

        # Get protocol filter
        proto_filter = self.traffic_proto_filter.get().lower()

        # Build traffic entries
        traffic_entries = []
        protocols = {}

        for entry in self.app.eve_event_buffer:
            data = entry['data']
            event = data.get('event_type', '')

            # Skip non-traffic events and DNS (has its own tab)
            if event not in ['http', 'tls', 'ssh', 'rdp', 'smb']:
                continue

            protocols[event] = protocols.get(event, 0) + 1

            # Apply filter
            if proto_filter != "all" and event != proto_filter:
                continue

            src_ip = data.get('src_ip', '')
            src_port = data.get('src_port', '')
            dest_ip = data.get('dest_ip', '')
            dest_port = data.get('dest_port', '')

            source = f"{src_ip}:{src_port}" if src_port else src_ip
            destination = f"{dest_ip}:{dest_port}" if dest_port else dest_ip

            host = ''
            details = ''

            if event == 'http':
                http = data.get('http', {})
                host = http.get('hostname', '')
                method = http.get('http_method', 'GET')
                url = http.get('url', '/')
                status = http.get('status', '')
                length = http.get('length', '')

                # Truncate URL if too long
                if len(url) > 40:
                    url = url[:37] + '...'
                details = f"{method} {url}"
                if status:
                    details += f" [{status}]"

            elif event == 'tls':
                tls = data.get('tls', {})
                host = tls.get('sni', '')
                version = tls.get('version', '')
                subject = tls.get('subject', '')
                ja3 = tls.get('ja3', {}).get('hash', '') if isinstance(tls.get('ja3'), dict) else ''

                details = version
                if ja3:
                    details += f" JA3:{ja3[:12]}..."
                if subject and len(details) < 30:
                    details += f" {subject[:20]}"

            elif event == 'ssh':
                ssh = data.get('ssh', {})
                client = ssh.get('client', {})
                server = ssh.get('server', {})
                client_ver = client.get('software_version', '') if isinstance(client, dict) else ''
                server_ver = server.get('software_version', '') if isinstance(server, dict) else ''
                details = f"Client: {client_ver}" if client_ver else ''
                if server_ver:
                    details += f" → Server: {server_ver}"

            elif event == 'smb':
                smb = data.get('smb', {})
                command = smb.get('command', '')
                filename = smb.get('filename', '')
                details = f"{command}"
                if filename:
                    details += f" {filename[:30]}"

            elif event == 'rdp':
                rdp = data.get('rdp', {})
                details = rdp.get('event_type', '')

            traffic_entries.append({
                'timestamp': entry['timestamp'],
                'protocol': event.upper(),
                'source': source,
                'destination': destination,
                'host': host,
                'details': details,
                'raw_data': data
            })

        # Update cache
        self.app.traffic_cache = {
            'protocols': protocols,
            'last_update': datetime.now()
        }

        # Sort by selected column
        sort_col = self.traffic_sort_column
        traffic_entries.sort(key=lambda x: x.get(sort_col, ''), reverse=self.traffic_sort_reverse)

        # Apply grouping unless ungrouped view is selected
        if not self.traffic_ungrouped.get():
            traffic_entries = self._group_traffic_by_destination(traffic_entries)

        # Limit to 300 entries
        traffic_entries = traffic_entries[:300]

        # Update stats
        total = len(traffic_entries)
        proto_breakdown = ', '.join(
            f"{p.upper()}: {c}" for p, c in sorted(protocols.items(), key=lambda x: -x[1])[:4]
        )
        self.traffic_stats_label.configure(text=f"{total} connections | {proto_breakdown}")

        # Build list of new values tuples for comparison
        new_values = []
        for entry in traffic_entries:
            new_values.append((
                entry['timestamp'],
                entry['protocol'],
                entry['source'],
                entry['destination'],
                entry['host'],
                entry['details']
            ))

        # Get current treeview values
        current_items = self.traffic_tree.get_children()
        current_values = [self.traffic_tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.traffic_data = traffic_entries
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.traffic_tree.treeview.yview()
        selected = self.traffic_tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.traffic_tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate treeview
        for item in current_items:
            self.traffic_tree.delete(item)

        self.traffic_data = traffic_entries

        for entry in traffic_entries:
            proto = entry['protocol'].lower()
            self.traffic_tree.insert('', tk.END, values=(
                entry['timestamp'],
                entry['protocol'],
                entry['source'],
                entry['destination'],
                entry['host'],
                entry['details']
            ), tags=(proto,))

        # Restore scroll position
        self.traffic_tree.treeview.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.traffic_tree.get_children():
                if self.traffic_tree.item(item, 'values') == selected_values:
                    self.traffic_tree.selection_set(item)
                    break

    def sort_traffic(self, column: str) -> None:
        """Sort traffic by column"""
        if self.traffic_sort_column == column:
            self.traffic_sort_reverse = not self.traffic_sort_reverse
        else:
            self.traffic_sort_column = column
            self.traffic_sort_reverse = True
        self.refresh()

    def _toggle_traffic_grouping(self) -> None:
        """Toggle between grouped and ungrouped traffic view"""
        current = self.traffic_ungrouped.get()
        self.traffic_ungrouped.set(not current)

        # Update button text to show current state
        if self.traffic_ungrouped.get():
            self.traffic_ungroup_btn.configure(text="󰘸 Group")
        else:
            self.traffic_ungroup_btn.configure(text="󰘷 Ungroup")

        self.refresh()

    def _group_traffic_by_destination(self, entries: List[Dict]) -> List[Dict]:
        """
        Group traffic entries by destination, appending x{count} for duplicates.

        Groups traffic with the same destination (IP:port), keeping the most recent
        occurrence and appending a count indicator (e.g., "192.168.1.1:443 x15").

        Args:
            entries: List of traffic entry dictionaries

        Returns:
            List of grouped traffic entries
        """
        if not entries:
            return entries

        # Group by destination
        dest_groups = {}
        for entry in entries:
            dest = entry.get('destination', '')
            if dest not in dest_groups:
                dest_groups[dest] = []
            dest_groups[dest].append(entry)

        # Build grouped result - use most recent entry from each group
        grouped_entries = []
        for dest, group in dest_groups.items():
            # Sort group by timestamp descending to get most recent
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()  # Copy to avoid modifying original

            count = len(group)
            if count > 1:
                # Append count to destination
                most_recent['destination'] = f"{dest} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        return grouped_entries

    def _show_traffic_context_menu(self, event) -> None:
        """Show context menu for traffic entries"""
        item = self.traffic_tree.treeview.identify_row(event.y)
        if not item:
            return

        self.traffic_tree.selection_set(item)
        values = self.traffic_tree.item(item, 'values')
        host = values[4]
        dest = values[3].split(':')[0] if ':' in values[3] else values[3]

        colors = self.get_colors()
        menu = tk.Menu(self.app.root, tearoff=0, bg=colors['bg_alt'], fg=colors['fg'])
        menu.add_command(label="View Details", command=lambda: self._show_traffic_details(None))
        menu.add_command(label="Copy Host", command=lambda: self.app.copy_to_clipboard(host))
        menu.add_separator()
        if host:
            menu.add_command(
                label=f"VirusTotal: {host}",
                command=lambda: self.app.lookup_virustotal(host)
            )
        menu.add_command(
            label=f"VirusTotal: {dest}",
            command=lambda: self.app.lookup_virustotal(dest)
        )
        menu.add_separator()
        menu.add_command(
            label=f"Search Alerts for: {host[:30] if host else dest}",
            command=lambda: [
                self.app.notebook.select(1),
                self.app.search_var.set(host if host else dest)
            ]
        )
        menu.post(event.x_root, event.y_root)

    def _show_traffic_details(self, event) -> None:
        """Show detailed traffic entry information"""
        selection = self.traffic_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.traffic_tree.item(item, 'values')
        timestamp, protocol, source = values[0], values[1], values[2]

        # Find raw data
        raw_data = None
        for entry in self.traffic_data:
            if entry['timestamp'] == timestamp and entry['protocol'] == protocol:
                raw_data = entry.get('raw_data', {})
                break

        if not raw_data:
            return

        colors = self.get_colors()

        # Create popup
        popup = tk.Toplevel(self.app.root)
        popup.title(f"{protocol} Connection Details")
        popup.geometry("650x500")
        popup.configure(bg=colors['bg'])

        # Header
        host = values[4] or values[3]
        ttk.Label(
            popup,
            text=f"󰖟 {protocol}: {host}",
            font=('Hack Nerd Font', 12, 'bold')
        ).pack(pady=10)

        # Connection info
        info_frame = ttk.LabelFrame(popup, text="Connection Details", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        conn_details = [
            ("Timestamp", timestamp),
            ("Protocol", protocol),
            ("Source", values[2]),
            ("Destination", values[3]),
            ("Host/SNI", values[4]),
        ]

        for i, (label, value) in enumerate(conn_details):
            ttk.Label(info_frame, text=f"{label}:").grid(row=i, column=0, sticky='w', padx=5)
            ttk.Label(info_frame, text=str(value)).grid(row=i, column=1, sticky='w', padx=5)

        # Protocol-specific details
        proto_data = raw_data.get(protocol.lower(), {})
        if proto_data:
            detail_frame = ttk.LabelFrame(popup, text=f"{protocol} Details", padding="10")
            detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            detail_text = self.app.widgets.create_textbox(
                detail_frame,
                height=12,
                bg=colors['bg_alt'],
                fg=colors['fg'],
                font=('Hack Nerd Font', 9)
            )
            detail_text.pack(fill=tk.BOTH, expand=True)

            if protocol == 'HTTP':
                detail_text.insert(tk.END, f"Method: {proto_data.get('http_method', 'N/A')}\n")
                detail_text.insert(tk.END, f"URL: {proto_data.get('url', 'N/A')}\n")
                detail_text.insert(tk.END, f"Status: {proto_data.get('status', 'N/A')}\n")
                detail_text.insert(tk.END, f"Content-Type: {proto_data.get('http_content_type', 'N/A')}\n")
                detail_text.insert(tk.END, f"User-Agent: {proto_data.get('http_user_agent', 'N/A')}\n")
                detail_text.insert(tk.END, f"Length: {proto_data.get('length', 'N/A')}\n")
                detail_text.insert(tk.END, f"Referrer: {proto_data.get('http_refer', 'N/A')}\n")

            elif protocol == 'TLS':
                detail_text.insert(tk.END, f"Version: {proto_data.get('version', 'N/A')}\n")
                detail_text.insert(tk.END, f"SNI: {proto_data.get('sni', 'N/A')}\n")
                detail_text.insert(tk.END, f"Subject: {proto_data.get('subject', 'N/A')}\n")
                detail_text.insert(tk.END, f"Issuer: {proto_data.get('issuerdn', 'N/A')}\n")
                detail_text.insert(tk.END, f"Fingerprint: {proto_data.get('fingerprint', 'N/A')}\n")
                ja3 = proto_data.get('ja3', {})
                if isinstance(ja3, dict):
                    detail_text.insert(tk.END, f"JA3 Hash: {ja3.get('hash', 'N/A')}\n")
                    detail_text.insert(tk.END, f"JA3 String: {ja3.get('string', 'N/A')}\n")

            elif protocol == 'SSH':
                client = proto_data.get('client', {})
                server = proto_data.get('server', {})
                if isinstance(client, dict):
                    detail_text.insert(tk.END, f"Client Proto: {client.get('proto_version', 'N/A')}\n")
                    detail_text.insert(tk.END, f"Client Software: {client.get('software_version', 'N/A')}\n")
                if isinstance(server, dict):
                    detail_text.insert(tk.END, f"Server Proto: {server.get('proto_version', 'N/A')}\n")
                    detail_text.insert(tk.END, f"Server Software: {server.get('software_version', 'N/A')}\n")

            else:
                # Generic JSON display
                detail_text.insert(tk.END, json.dumps(proto_data, indent=2))

        # Close button
        self.app.widgets.create_button(
            popup,
            text="Close",
            command=popup.destroy
        ).pack(pady=10)
