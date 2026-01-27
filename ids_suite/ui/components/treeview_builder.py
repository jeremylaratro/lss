"""
Treeview Builder Component
Encapsulates the repeated Treeview creation pattern from main_window.py
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, List, Tuple, Optional, Callable, Any


class TreeviewWrapper:
    """
    Wrapper for Treeview with scrollbars and common operations.

    Provides a cleaner interface for the treeview + scrollbar pattern
    that appears throughout main_window.py.
    """

    def __init__(self, treeview: ttk.Treeview, frame: ttk.Frame):
        """
        Initialize wrapper.

        Args:
            treeview: The ttk.Treeview instance
            frame: The container frame with grid layout
        """
        self.treeview = treeview
        self.frame = frame
        self.sort_column: Optional[str] = None
        self.sort_reverse: bool = False

    def insert(self, *args, **kwargs):
        """Proxy to treeview.insert()"""
        return self.treeview.insert(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Proxy to treeview.delete()"""
        return self.treeview.delete(*args, **kwargs)

    def get_children(self, *args, **kwargs):
        """Proxy to treeview.get_children()"""
        return self.treeview.get_children(*args, **kwargs)

    def item(self, *args, **kwargs):
        """Proxy to treeview.item()"""
        return self.treeview.item(*args, **kwargs)

    def selection(self, *args, **kwargs):
        """Proxy to treeview.selection()"""
        return self.treeview.selection(*args, **kwargs)

    def bind(self, *args, **kwargs):
        """Proxy to treeview.bind()"""
        return self.treeview.bind(*args, **kwargs)

    def tag_configure(self, *args, **kwargs):
        """Proxy to treeview.tag_configure()"""
        return self.treeview.tag_configure(*args, **kwargs)

    def clear(self):
        """Clear all items from treeview"""
        for item in self.treeview.get_children():
            self.treeview.delete(item)

    def set_sort_state(self, column: str, reverse: bool = False):
        """
        Set current sort state.

        Args:
            column: Column name to sort by
            reverse: Sort in reverse order
        """
        self.sort_column = column
        self.sort_reverse = reverse


class TreeviewBuilder:
    """
    Builder for creating Treeview widgets with the standard pattern.

    Extracts the repeated Treeview creation pattern:
    1. Create frame
    2. Create treeview with columns
    3. Configure headings (text, sort command)
    4. Configure column widths
    5. Add scrollbars (vertical and horizontal)
    6. Grid layout
    7. Configure tags for colors
    8. Bind events
    """

    def __init__(self, colors: Optional[Dict[str, str]] = None):
        """
        Initialize builder.

        Args:
            colors: Color scheme dictionary (from SecurityControlPanel)
        """
        self.colors = colors or {}

    def create(
        self,
        parent: tk.Widget,
        columns: List[Tuple[str, str, int, int, Optional[str]]],
        style: str = 'Treeview',
        sort_callback: Optional[Callable[[str], None]] = None,
        tags: Optional[Dict[str, str]] = None,
        events: Optional[Dict[str, Callable]] = None,
        show_tree: bool = False
    ) -> TreeviewWrapper:
        """
        Create a treeview with scrollbars using the standard pattern.

        Args:
            parent: Parent widget
            columns: List of tuples (col_id, heading_text, width, minwidth, anchor)
                    anchor is optional and defaults to 'w' (west/left)
            style: Treeview style name
            sort_callback: Callback function for column sorting, receives column name
            tags: Dictionary of tag_name -> foreground_color for tag configuration
            events: Dictionary of event_name -> callback for event binding
            show_tree: If True, show tree column (default False for table view)

        Returns:
            TreeviewWrapper instance with treeview and frame

        Example:
            builder = TreeviewBuilder(colors)
            tree = builder.create(
                parent=frame,
                columns=[
                    ('timestamp', 'Timestamp', 140, 100, None),
                    ('signature', 'Signature', 320, 150, None),
                    ('source', 'Source', 140, 100, None),
                ],
                sort_callback=self.sort_alerts,
                tags={
                    'high': colors['red'],
                    'medium': colors['orange'],
                    'low': colors['yellow']
                },
                events={
                    '<Double-1>': self.show_details,
                    '<Button-3>': self.show_context_menu
                }
            )
        """
        # Create container frame
        frame = ttk.Frame(parent)

        # Extract column IDs
        col_ids = [col[0] for col in columns]

        # Create Treeview
        show = 'tree headings' if show_tree else 'headings'
        tree = ttk.Treeview(frame, columns=col_ids, show=show, style=style)

        # Configure columns and headings
        for col in columns:
            col_id = col[0]
            heading_text = col[1]
            width = col[2]
            minwidth = col[3]
            anchor = col[4] if len(col) > 4 and col[4] else 'w'

            # Configure heading with optional sort command
            if sort_callback:
                tree.heading(
                    col_id,
                    text=heading_text,
                    command=lambda c=col_id: sort_callback(c)
                )
            else:
                tree.heading(col_id, text=heading_text)

            # Configure column
            tree.column(col_id, width=width, minwidth=minwidth, anchor=anchor)

        # Add scrollbars
        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        # Grid layout
        tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        # Configure tags for colors
        if tags:
            for tag_name, color in tags.items():
                tree.tag_configure(tag_name, foreground=color)

        # Bind events
        if events:
            for event_name, callback in events.items():
                tree.bind(event_name, callback)

        return TreeviewWrapper(tree, frame)

    def create_simple(
        self,
        parent: tk.Widget,
        columns: List[str],
        headings: List[str],
        widths: Optional[List[int]] = None,
        style: str = 'Treeview'
    ) -> TreeviewWrapper:
        """
        Simplified treeview creation for basic use cases.

        Args:
            parent: Parent widget
            columns: List of column IDs
            headings: List of heading texts (same order as columns)
            widths: Optional list of column widths (defaults to 100 for all)
            style: Treeview style name

        Returns:
            TreeviewWrapper instance

        Example:
            tree = builder.create_simple(
                parent=frame,
                columns=['name', 'value', 'status'],
                headings=['Name', 'Value', 'Status'],
                widths=[150, 100, 80]
            )
        """
        if widths is None:
            widths = [100] * len(columns)

        # Build column tuples
        col_tuples = [
            (col_id, heading, width, 50, None)
            for col_id, heading, width in zip(columns, headings, widths)
        ]

        return self.create(parent, col_tuples, style=style)


def create_standard_alerts_tree(
    parent: tk.Widget,
    colors: Dict[str, str],
    sort_callback: Callable[[str], None],
    on_double_click: Callable,
    on_right_click: Callable
) -> TreeviewWrapper:
    """
    Factory function to create the standard alerts treeview.

    This replicates the alerts treeview pattern from main_window.py.

    Args:
        parent: Parent widget
        colors: Color scheme dictionary
        sort_callback: Callback for column sorting
        on_double_click: Callback for double-click (show details)
        on_right_click: Callback for right-click (context menu)

    Returns:
        TreeviewWrapper for alerts
    """
    builder = TreeviewBuilder(colors)

    return builder.create(
        parent=parent,
        columns=[
            ('timestamp', 'Time', 70, 60, None),
            ('sev', 'Sev', 35, 30, 'center'),
            ('signature', 'Signature', 280, 150, None),
            ('source', 'Source', 130, 90, None),
            ('destination', 'Destination', 130, 90, None),
            ('category', 'Cat', 50, 40, None),
            ('intel', 'Intel', 90, 70, 'center'),
        ],
        style='Alerts.Treeview',
        sort_callback=sort_callback,
        tags={
            'high': colors['red'],
            'medium': colors['orange'],
            'low': colors['yellow'],
        },
        events={
            '<Double-1>': on_double_click,
            '<Button-3>': on_right_click,
        }
    )


def create_standard_traffic_tree(
    parent: tk.Widget,
    colors: Dict[str, str],
    sort_callback: Callable[[str], None]
) -> TreeviewWrapper:
    """
    Factory function to create the standard traffic treeview.

    Args:
        parent: Parent widget
        colors: Color scheme dictionary
        sort_callback: Callback for column sorting

    Returns:
        TreeviewWrapper for traffic
    """
    builder = TreeviewBuilder(colors)

    return builder.create(
        parent=parent,
        columns=[
            ('timestamp', 'Timestamp', 140, 100, None),
            ('protocol', 'Proto', 60, 50, 'center'),
            ('source', 'Source', 130, 100, None),
            ('destination', 'Destination', 130, 100, None),
            ('host', 'Host/SNI', 200, 150, None),
            ('details', 'Details', 250, 150, None),
        ],
        style='Alerts.Treeview',
        sort_callback=sort_callback,
        tags={
            'http': colors['green'],
            'tls': colors['cyan'],
            'ssh': colors['yellow'],
            'smb': colors['purple'],
            'rdp': colors['orange'],
        }
    )


def create_standard_dns_tree(
    parent: tk.Widget,
    colors: Dict[str, str],
    sort_callback: Callable[[str], None]
) -> TreeviewWrapper:
    """
    Factory function to create the standard DNS treeview.

    Args:
        parent: Parent widget
        colors: Color scheme dictionary
        sort_callback: Callback for column sorting

    Returns:
        TreeviewWrapper for DNS queries
    """
    builder = TreeviewBuilder(colors)

    return builder.create(
        parent=parent,
        columns=[
            ('timestamp', 'Timestamp', 140, 100, None),
            ('type', 'Type', 60, 50, 'center'),
            ('domain', 'Domain', 250, 150, None),
            ('answer', 'Answer', 180, 100, None),
            ('rcode', 'RCode', 80, 60, 'center'),
            ('source', 'Source IP', 120, 100, None),
        ],
        style='Alerts.Treeview',
        sort_callback=sort_callback,
        tags={
            'A': colors['green'],
            'AAAA': colors['cyan'],
            'CNAME': colors['yellow'],
            'MX': colors['purple'],
            'TXT': colors['orange'],
        }
    )
