"""
DNS Tab Component
Extracted from main_window.py - Provides DNS query analysis and monitoring
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime
from typing import TYPE_CHECKING

from ids_suite.ui.tabs.base_tab import BaseTab
from ids_suite.ui.components.treeview_builder import TreeviewBuilder

if TYPE_CHECKING:
    from ids_suite.ui.main_window import SecurityControlPanel


class DNSTab(BaseTab):
    """
    DNS Query Analysis Tab

    Features:
    - Real-time DNS query monitoring from EVE buffer
    - Type filtering (A, AAAA, CNAME, MX, TXT, PTR, NS, SOA)
    - Domain grouping with query counts
    - Sortable columns
    - Detailed query inspection
    - Context menu with VirusTotal lookup
    - Color-coded response codes (SERVFAIL, NXDOMAIN)
    """

    def __init__(self, parent: tk.Widget, app: 'SecurityControlPanel'):
        """
        Initialize DNS tab.

        Args:
            parent: Parent widget (notebook)
            app: Main SecurityControlPanel instance
        """
        # Initialize state before calling super (which calls _create_widgets)
        self.dns_data = []  # Current DNS entries shown in tree
        self.sort_column = 'timestamp'
        self.sort_reverse = True

        super().__init__(parent, app)

    def _create_widgets(self) -> None:
        """Create DNS tab UI components"""
        # Header with controls
        header_frame = ttk.Frame(self.frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            header_frame,
            text="󰇖 DNS Query Analysis",
            style='Title.TLabel'
        ).pack(side=tk.LEFT)

        # Type filter
        self.app.widgets.create_label(header_frame, text="Type:").pack(
            side=tk.LEFT, padx=(20, 5)
        )
        self.type_filter = tk.StringVar(value="all")
        dns_type_combo = ttk.Combobox(
            header_frame,
            textvariable=self.type_filter,
            values=["all", "A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SOA"],
            width=8,
            state='readonly'
        )
        dns_type_combo.pack(side=tk.LEFT, padx=(0, 10))
        dns_type_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh())

        # Grouping toggle button
        self.ungrouped = tk.BooleanVar(value=False)
        self.ungroup_btn = self.app.widgets.create_button(
            header_frame,
            text="󰘷 Ungroup",
            command=self._toggle_grouping
        )
        self.ungroup_btn.pack(side=tk.LEFT, padx=(10, 5))

        # Refresh button
        self.app.widgets.create_button(
            header_frame,
            text="󰑐 Refresh",
            command=self.refresh
        ).pack(side=tk.RIGHT, padx=5)

        # Stats label
        self.stats_label = ttk.Label(
            header_frame,
            text="",
            foreground=self.app.colors['cyan']
        )
        self.stats_label.pack(side=tk.RIGHT, padx=10)

        # Create DNS treeview using TreeviewBuilder
        builder = TreeviewBuilder(self.app.colors)
        self.tree = builder.create(
            parent=self.frame,
            columns=[
                ('timestamp', 'Timestamp', 140, 100, None),
                ('type', 'Type', 60, 50, 'center'),
                ('domain', 'Domain', 250, 150, None),
                ('answer', 'Answer', 180, 100, None),
                ('rcode', 'RCode', 80, 60, 'center'),
                ('source', 'Source IP', 120, 100, None),
            ],
            style='Alerts.Treeview',
            sort_callback=self._sort_by_column,
            tags={
                'error': self.app.colors['red'],
                'nxdomain': self.app.colors['orange'],
            },
            events={
                '<Button-3>': self._show_context_menu,
                '<Double-1>': self._show_details,
            }
        )
        self.tree.frame.pack(fill=tk.BOTH, expand=True)

    def refresh(self) -> None:
        """Refresh DNS data from EVE buffer"""
        # Update the shared EVE buffer first
        self.app._update_eve_buffer()

        # Get type filter
        type_filter = self.type_filter.get()

        # Build DNS entries list
        dns_entries = []
        query_types = {}

        for entry in self.app.eve_event_buffer:
            data = entry['data']
            if data.get('event_type') == 'dns':
                dns = data.get('dns', {})
                rrname = dns.get('rrname', '')
                rrtype = dns.get('rrtype', 'A')
                rcode = dns.get('rcode', '')

                # Count query types
                if rrtype:
                    query_types[rrtype] = query_types.get(rrtype, 0) + 1

                # Apply type filter
                if type_filter != "all" and rrtype != type_filter:
                    continue

                # Extract answer from answers array or rdata
                answers = dns.get('answers', [])
                answer = ''
                if answers:
                    # Get first answer rdata
                    first_answer = answers[0] if isinstance(answers, list) else {}
                    answer = first_answer.get('rdata', '') if isinstance(first_answer, dict) else str(first_answer)
                else:
                    answer = dns.get('rdata', '')

                # Truncate answer if too long
                if len(answer) > 30:
                    answer = answer[:27] + '...'

                dns_entries.append({
                    'timestamp': entry['timestamp'],
                    'type': rrtype,
                    'domain': rrname,
                    'answer': answer,
                    'rcode': rcode,
                    'source': data.get('src_ip', ''),
                    'raw_data': data
                })

        # Update cache for reference
        self.app.dns_cache = {
            'query_types': query_types,
            'last_update': datetime.now()
        }

        # Sort by selected column
        dns_entries.sort(
            key=lambda x: x.get(self.sort_column, ''),
            reverse=self.sort_reverse
        )

        # Apply grouping unless ungrouped view is selected
        if not self.ungrouped.get():
            dns_entries = self._group_by_domain(dns_entries)

        # Limit to 300 entries for performance
        dns_entries = dns_entries[:300]

        # Update stats label
        total = len(dns_entries)
        type_breakdown = ', '.join(
            f"{t}: {c}" for t, c in sorted(query_types.items(), key=lambda x: -x[1])[:4]
        )
        self.stats_label.configure(text=f"{total} queries | {type_breakdown}")

        # Build list of new values tuples for comparison
        new_values = []
        for entry in dns_entries:
            new_values.append((
                entry['timestamp'],
                entry['type'],
                entry['domain'],
                entry['answer'],
                entry['rcode'],
                entry['source']
            ))

        # Get current treeview values
        current_items = self.tree.get_children()
        current_values = [self.tree.item(item, 'values') for item in current_items]

        # Compare - only update if data changed (silent refresh)
        if new_values == current_values:
            self.dns_data = dns_entries
            return

        # Data changed - save scroll position and selection
        scroll_pos = self.tree.treeview.yview()
        selected = self.tree.selection()
        selected_values = None
        if selected:
            try:
                selected_values = self.tree.item(selected[0], 'values')
            except:
                pass

        # Clear and repopulate treeview
        self.tree.clear()
        self.dns_data = dns_entries

        for entry in dns_entries:
            rcode = entry['rcode']
            if rcode in ('SERVFAIL', 'REFUSED'):
                tag = 'error'
            elif rcode == 'NXDOMAIN':
                tag = 'nxdomain'
            else:
                tag = ''

            self.tree.insert('', tk.END, values=(
                entry['timestamp'],
                entry['type'],
                entry['domain'],
                entry['answer'],
                entry['rcode'],
                entry['source']
            ), tags=(tag,) if tag else ())

        # Restore scroll position
        self.tree.treeview.yview_moveto(scroll_pos[0])

        # Restore selection if the same item still exists
        if selected_values:
            for item in self.tree.get_children():
                if self.tree.item(item, 'values') == selected_values:
                    self.tree.selection_set(item)
                    break

    def _sort_by_column(self, column: str) -> None:
        """
        Sort DNS entries by column.

        Args:
            column: Column name to sort by
        """
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = True
        self.refresh()

    def _toggle_grouping(self) -> None:
        """Toggle between grouped and ungrouped DNS view"""
        current = self.ungrouped.get()
        self.ungrouped.set(not current)

        if self.ungrouped.get():
            self.ungroup_btn.configure(text="󰘸 Group")
        else:
            self.ungroup_btn.configure(text="󰘷 Ungroup")

        self.refresh()

    def _group_by_domain(self, entries: list) -> list:
        """
        Group DNS entries by domain, appending x{count} for duplicates.

        Args:
            entries: List of DNS entry dictionaries

        Returns:
            List of grouped DNS entries
        """
        if not entries:
            return entries

        # Group by domain
        domain_groups = {}
        for entry in entries:
            domain = entry.get('domain', '')
            if domain not in domain_groups:
                domain_groups[domain] = []
            domain_groups[domain].append(entry)

        # Build grouped result
        grouped_entries = []
        for domain, group in domain_groups.items():
            group.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            most_recent = group[0].copy()

            count = len(group)
            if count > 1:
                most_recent['domain'] = f"{domain} x{count}"
                most_recent['_group_count'] = count

            grouped_entries.append(most_recent)

        grouped_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return grouped_entries

    def _show_context_menu(self, event) -> None:
        """Show context menu for DNS entries"""
        item = self.tree.treeview.identify_row(event.y)
        if not item:
            return

        self.tree.selection_set(item)
        values = self.tree.item(item, 'values')
        domain = values[2]
        source_ip = values[5]

        menu = tk.Menu(self.app.root, tearoff=0, bg=self.app.colors['bg_alt'], fg=self.app.colors['fg'])
        menu.add_command(label="View Details", command=lambda: self._show_details(None))
        menu.add_command(label="Copy Domain", command=lambda: self.app.copy_to_clipboard(domain))
        menu.add_separator()
        menu.add_command(
            label=f"Search Alerts for: {domain[:30]}",
            command=lambda: [
                self.app.notebook.select(1),
                self.app.search_var.set(domain)
            ]
        )
        menu.add_command(
            label=f"VirusTotal: {domain}",
            command=lambda: self.app.lookup_virustotal(domain)
        )
        if source_ip:
            menu.add_command(
                label=f"VirusTotal: {source_ip}",
                command=lambda: self.app.lookup_virustotal(source_ip)
            )
        menu.post(event.x_root, event.y_root)

    def _show_details(self, event) -> None:
        """Show detailed DNS entry information"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.tree.item(item, 'values')
        timestamp, qtype, domain = values[0], values[1], values[2]

        # Find raw data
        raw_data = None
        for entry in self.dns_data:
            if entry['timestamp'] == timestamp and entry['domain'] == domain:
                raw_data = entry.get('raw_data', {})
                break

        if not raw_data:
            return

        # Create popup
        popup = tk.Toplevel(self.app.root)
        popup.title(f"DNS Query - {domain}")
        popup.geometry("600x450")
        popup.configure(bg=self.app.colors['bg'])

        # Header
        ttk.Label(
            popup,
            text=f"󰇖 {qtype} Query: {domain}",
            font=('Hack Nerd Font', 12, 'bold')
        ).pack(pady=10)

        # Info frame
        info_frame = ttk.LabelFrame(popup, text="Query Details", padding="10")
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        dns_data = raw_data.get('dns', {})
        details = [
            ("Timestamp", timestamp),
            ("Query Type", qtype),
            ("Domain", domain),
            ("Response Code", dns_data.get('rcode', 'N/A')),
            ("Source IP", raw_data.get('src_ip', 'N/A')),
            ("Dest IP", raw_data.get('dest_ip', 'N/A')),
            ("TTL", dns_data.get('ttl', 'N/A')),
        ]

        for i, (label, value) in enumerate(details):
            ttk.Label(info_frame, text=f"{label}:").grid(
                row=i, column=0, sticky='w', padx=5
            )
            ttk.Label(info_frame, text=str(value)).grid(
                row=i, column=1, sticky='w', padx=5
            )

        # Answers section
        answers = dns_data.get('answers', [])
        if answers:
            ans_frame = ttk.LabelFrame(
                popup,
                text=f"Answers ({len(answers)})",
                padding="10"
            )
            ans_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            ans_text = self.app.widgets.create_textbox(
                ans_frame,
                height=8,
                bg=self.app.colors['bg_alt'],
                fg=self.app.colors['fg'],
                font=('Hack Nerd Font', 9)
            )
            ans_text.pack(fill=tk.BOTH, expand=True)

            for ans in answers:
                if isinstance(ans, dict):
                    rdata = ans.get('rdata', 'N/A')
                    rtype = ans.get('rrtype', '')
                    ttl = ans.get('ttl', '')
                    ans_text.insert(tk.END, f"  {rtype:8} TTL={ttl:6} → {rdata}\n")
                else:
                    ans_text.insert(tk.END, f"  {ans}\n")

        # Close button
        self.app.widgets.create_button(
            popup,
            text="Close",
            command=popup.destroy
        ).pack(pady=10)
